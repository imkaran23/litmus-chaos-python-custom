import pkg.types.types as types
import pkg.curl_chaos.types.types as experimentDetails
import pkg.curl_chaos.environment.environment as experimentEnv
import pkg.events.events as events
import pkg.status.application as application
import pkg.result.chaosresult as chaosResults
import pkg.utils.common.common as common

import requests
import logging
from requests.auth import HTTPDigestAuth
import botocore
import datetime
from dateutil.tz import tzlocal
import botocore.session
from botocore.credentials import AssumeRoleCredentialFetcher, DeferredRefreshableCredentials
import boto3
import os
from random2 import randrange


# Experiment contains steps to inject chaos
def Experiment(clients):
    # Initialising expermentDetails, resultDetails, eventsDetails, chaosDetails, status and result objects
    experiment_status = ''
    experimentsDetails = experimentDetails.ExperimentDetails()
    resultDetails = types.ResultDetails()
    eventsDetails = types.EventDetails()
    chaosDetails = types.ChaosDetails()
    status = application.Application()
    result = chaosResults.ChaosResults()

    # Fetching all the ENV passed from the runner pod
    experimentEnv.GetENV(experimentsDetails)

    # Intialise the chaos attributes
    experimentEnv.InitialiseChaosVariables(chaosDetails, experimentsDetails)

    # Intialise Chaos Result Parameters
    types.SetResultAttributes(resultDetails, chaosDetails)

    # Updating the chaos result in the beginning of experiment
    logging.info("[PreReq]: Updating the chaos result of %s experiment (SOT)", (experimentsDetails.ExperimentName))
    err = result.ChaosResult(chaosDetails, resultDetails, "SOT", clients)
    if err != None:
        logging.error("Unable to Create the Chaos Result, err: %s", (err))
        failStep = "Updating the chaos result of custom experiment (SOT)"
        result.RecordAfterFailure(chaosDetails, resultDetails, failStep, eventsDetails, clients)
        return

    #######################################################
    def assumed_role_session(role_arn, base_session=None):
        logging.info('executing assumed_role_session')
        base_session = base_session or boto3.session.Session()._session
        fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
            client_creator=base_session.create_client,
            source_credentials=base_session.get_credentials(),
            role_arn=role_arn,
            extra_args={
                #    'RoleSessionName': None # set this if you want something non-default
            }
        )
        creds = botocore.credentials.DeferredRefreshableCredentials(
            method='assume-role',
            refresh_using=fetcher.fetch_credentials,
            time_fetcher=lambda: datetime.datetime.now(tzlocal())
        )
        botocore_session = botocore.session.Session()
        botocore_session._credentials = creds
        logging.info('getting details for botocore_session')
        logging.info('botocore_session', botocore_session)
        return boto3.Session(botocore_session=botocore_session)

    #########################################
    def reboot_kafka_broker():
        logging.info('reboot_kafka_broker')
        experiment_status = 'Failed'


        msk = boto3.client('kafka',
                               aws_access_key_id=experimentsDetails.AWSAccessKeyId,
                               aws_secret_access_key=experimentsDetails.AWSSecretAccessKey,
                               region_name=experimentsDetails.KafkaAwsRegion)

        random_number = randrange(1, 3)

        response = msk.reboot_broker(
            BrokerIds=[
                str(random_number)
            ],
            ClusterArn=experimentsDetails.KafkaClusterARN
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            experiment_status = 'Succeeded'

    ##########################################
    def execute_elastic_cache_failover():
        logging.info('execute_elastic_cache_failover')
        experiment_status = 'Failed'

        elastic_cache_client = boto3.client('elasticache',
                                            aws_access_key_id=experimentsDetails.AWSAccessKeyId,
                                            aws_secret_access_key=experimentsDetails.AWSSecretAccessKey,
                                            region_name=experimentsDetails.RedisAwsRegion)


        response = elastic_cache_client.test_failover(ReplicationGroupId=experimentsDetails.RedisReplicationGroupId,
                                                  NodeGroupId=experimentsDetails.RedisNodeGroupId)
        print(response.status_code)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            experiment_status = 'Succeeded'

    #############################################################

    def terminate_mongo_atlas_instance():
        print("terminating mongo using generic code")
        experiment_status = 'Failed'

        response = requests.post(
            experimentsDetails.MongoAtlasURL
            , auth=HTTPDigestAuth(experimentsDetails.MongoAtlasPublicKey, experimentsDetails.MongoAtlasPrivateKey))

        if (response.status_code == 200):
            experiment_status = 'Succeeded'

    #################################################

    if experimentsDetails.Experiment == 'ATLAS':
        print(experimentsDetails.Experiment)
        terminate_mongo_atlas_instance()
    elif experimentsDetails.Experiment == 'KAFKA':
        print(experimentsDetails.Experiment)
        reboot_kafka_broker()
    elif experimentsDetails.Experiment == 'REDIS':
        print(experimentsDetails.Experiment)
        execute_elastic_cache_failover()
    else:
        logging.error("Please enter valid choice for EXPERIMENT_NAME [ATLAS, KAFKA, REDIS] ")

    # Set the chaos result uid
    result.SetResultUID(resultDetails, chaosDetails, clients)

    # generating the event in chaosresult to marked the verdict as awaited
    msg = "Experiment " + experimentsDetails.ExperimentName + ", Result Awaited"
    types.SetResultEventAttributes(eventsDetails, types.AwaitedVerdict, msg, "Normal", resultDetails)
    events.GenerateEvents(eventsDetails, chaosDetails, "ChaosResult", clients)

    # DISPLAY THE APP INFORMATION
    logging.info("[Info]: The application information is as follows Namespace=%s, Label=%s, Ramp Time=%s",
                 experimentsDetails.AppNS, experimentsDetails.AppLabel, experimentsDetails.RampTime)

    # Calling AbortWatcher, it will continuously watch for the abort signal and generate the required and result
    common.AbortWatcher(experimentsDetails.ExperimentName, resultDetails, chaosDetails, eventsDetails, clients)

    logging.info("[Confirmation]: %s chaos has been injected successfully", experimentsDetails.ExperimentName)

    if experiment_status != 'Failed':
        resultDetails.Verdict = "Pass"

    if experimentsDetails.EngineName != "":
        # marking AUT as running, as we already checked the status of application under test
        msg = "AUT: Running"

        # generating post chaos event
        types.SetEngineEventAttributes(eventsDetails, types.PostChaosCheck, msg, "Normal", chaosDetails)
        events.GenerateEvents(eventsDetails, chaosDetails, "ChaosEngine", clients)

    # Updating the chaosResult in the end of experiment
    logging.info("[The End]: Updating the chaos result of %s experiment (EOT)", experimentsDetails.ExperimentName)
    err = result.ChaosResult(chaosDetails, resultDetails, "EOT", clients)
    if err != None:
        logging.error("Unable to Update the Chaos Result, err: %s", err)
        return

    # generating the event in chaosresult to marked the verdict as pass/fail
    msg = "Experiment " + experimentsDetails.ExperimentName + ", Result " + resultDetails.Verdict
    reason = types.PassVerdict
    eventType = "Normal"
    if resultDetails.Verdict != "Pass":
        reason = types.FailVerdict
        eventType = "Warning"

    types.SetResultEventAttributes(eventsDetails, reason, msg, eventType, resultDetails)
    events.GenerateEvents(eventsDetails, chaosDetails, "ChaosResult", clients)
    if experimentsDetails.EngineName != "":
        msg = experimentsDetails.ExperimentName + " experiment has been " + resultDetails.Verdict + "ed"
        types.SetEngineEventAttributes(eventsDetails, types.Summary, msg, "Normal", chaosDetails)
        events.GenerateEvents(eventsDetails, chaosDetails, "ChaosEngine", clients)
