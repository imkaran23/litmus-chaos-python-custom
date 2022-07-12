import pkg.types.types  as types
import pkg.curl_chaos.types.types as experimentDetails
import pkg.curl_chaos.environment.environment as experimentEnv
import pkg.events.events as events
import logging
import pkg.status.application as application
import chaosLib.litmus.curl_exec_chaos.lib.curl_exec_chaos as litmusLIB
import pkg.result.chaosresult as chaosResults
import pkg.utils.common.common as common
import requests
from requests.auth import HTTPDigestAuth
import requests
import random
import base64
import hvac
import os
import logging
from requests.auth import HTTPDigestAuth
import botocore
import datetime
from dateutil.tz import tzlocal
import botocore.session
from botocore.credentials import AssumeRoleCredentialFetcher, DeferredRefreshableCredentials
import boto3
from random2 import randrange

# Experiment contains steps to inject chaos
def Experiment(clients):

	# Initialising expermentDetails, resultDetails, eventsDetails, chaosDetails, status and result objects
	experimentsDetails = experimentDetails.ExperimentDetails()
	resultDetails = types.ResultDetails()
	eventsDetails = types.EventDetails()
	chaosDetails = types.ChaosDetails()
	status = application.Application()
	result = chaosResults.ChaosResults()
	
	#Fetching all the ENV passed from the runner pod
	experimentEnv.GetENV(experimentsDetails)


	# Intialise the chaos attributes
	experimentEnv.InitialiseChaosVariables(chaosDetails, experimentsDetails)
	
	# Intialise Chaos Result Parameters
	types.SetResultAttributes(resultDetails, chaosDetails)
	
	#Updating the chaos result in the beginning of experiment
	logging.info("[PreReq]: Updating the chaos result of %s experiment (SOT)",(experimentsDetails.ExperimentName))
	err = result.ChaosResult(chaosDetails, resultDetails, "SOT", clients)
	if err != None:
		logging.error("Unable to Create the Chaos Result, err: %s",(err))
		failStep = "Updating the chaos result of pod-delete experiment (SOT)"
		result.RecordAfterFailure(chaosDetails, resultDetails, failStep, eventsDetails, clients)
		return

	def get_hvac_client():
		client = hvac.Client(
			url=os.environ['VAULT_URL'],
			token=os.environ['VAULT_TOKEN']
		)
		return client

	#--------------------------------------------------------------------------

	#------------------------------------------------------
	def read_vault_secrets(secret_path, transit_key):
		client = get_hvac_client()
		print(transit_key)
		mount_point = 'secret/'
		response = client.secrets.kv.read_secret_version(
			path=secret_path,
			mount_point=mount_point
		)

		return response


	#------------------------------------------------------

	##################################################
	def decrypt_data_using_transit_key(transit_key, encrypted_text):
		client = get_hvac_client()
		decrypt_data_response = client.secrets.transit.decrypt_data(
			name=transit_key,
			ciphertext=encrypted_text,
		)
		plaintext = decrypt_data_response['data']['plaintext']
		print('Decrypted plaintext is: {text}'.format(text=plaintext))
		return plaintext

	###################################################

	################################################
	def get_base64_decoded_str(base64_message):
		base64_bytes = base64_message.encode('ascii')
		message_bytes = base64.b64decode(base64_bytes)
		message = message_bytes.decode('ascii')
		return message

	####################################################
	def terminate_mongo_atlas_instance():
			print("terminating mongo using generic code")
			response = read_vault_secrets(experimentsDetails.MongoAtlasSecretPath,
										  experimentsDetails.MongoAtlasSecretTransitPath)
			mongo_atlas_username = response['data']['data']['MONGODB_ATLAS_PUBLIC_KEY']
			mongo_atlas_password = response['data']['data']['MONGODB_ATLAS_PRIVATE_KEY']

			base64_encoded_mongo_atlas_username = decrypt_data_using_transit_key(
				experimentsDetails.MongoAtlasSecretTransitPath, mongo_atlas_username)
			base64_encoded_mongo_atlas_password = decrypt_data_using_transit_key(
				experimentsDetails.MongoAtlasSecretTransitPath, mongo_atlas_password)

			decoded_username = get_base64_decoded_str(base64_encoded_mongo_atlas_username)
			decoded_password = get_base64_decoded_str(base64_encoded_mongo_atlas_password)

			experiment_status = 'Failed'

			print(response.json())
			print(response.status_code)
			response = requests.post(
				experimentsDetails.MongoAtlasURL
				, auth=HTTPDigestAuth(decoded_username, decoded_password))

			if (response.status_code == 200):
				experiment_status = 'Succeeded'
	#################################################

	if experimentsDetails.Experiment == 'ATLAS':
		print(experimentsDetails.Experiment)
		experiment_status = 'Failed'
		response = requests.post(
			"https://cloud.mongodb.com/api/atlas/v1.5/groups/61126f8862a44c58592d010c/clusters/atlas-techx-ota-dev/restartPrimaries?pretty=true"
			, auth=HTTPDigestAuth('rdpaqzxs', '35ce97cd-9818-448c-bf49-5179fb177df4'))

		print(response.status_code)

		if (response.status_code == 200):
			experiment_status = 'Succeeded'

		print(experiment_status)
	else:
		logging.error("Please enter valid choice[ALL, POD_TERMINATION, NETWORK_LAG, ATLAS, KAFKA, REDIS] ")


	# Set the chaos result uid
	result.SetResultUID(resultDetails, chaosDetails, clients)


	# generating the event in chaosresult to marked the verdict as awaited
	msg = "Experiment " + experimentsDetails.ExperimentName + ", Result Awaited"
	types.SetResultEventAttributes(eventsDetails, types.AwaitedVerdict, msg, "Normal", resultDetails)
	events.GenerateEvents(eventsDetails, chaosDetails, "ChaosResult", clients)

	#DISPLAY THE APP INFORMATION
	logging.info("[Info]: The application information is as follows Namespace=%s, Label=%s, Ramp Time=%s",experimentsDetails.AppNS,experimentsDetails.AppLabel,experimentsDetails.RampTime)
	
	# Calling AbortWatcher, it will continuously watch for the abort signal and generate the required and result
	common.AbortWatcher(experimentsDetails.ExperimentName, resultDetails, chaosDetails, eventsDetails, clients)

	
	# Including the litmus lib for pod-delete
	'''if experimentsDetails.ChaosLib == "litmus" :
		err = litmusLIB.PrepareChaos(experimentsDetails, resultDetails, eventsDetails, chaosDetails, clients)
		if err != None:
			logging.error("Chaos injection failed, err: %s",(err))
			failStep = "failed in chaos injection phase"
			result.RecordAfterFailure(chaosDetails, resultDetails, failStep, eventsDetails, clients)
			return
		
	else:
		logging.info("[Invalid]: Please Provide the correct LIB")
		failStep = "no match found for specified lib"
		result.RecordAfterFailure(chaosDetails, resultDetails, failStep, eventsDetails, clients)
		return '''
	
	logging.info("[Confirmation]: %s chaos has been injected successfully", experimentsDetails.ExperimentName)
	resultDetails.Verdict = "Pass"


	if experimentsDetails.EngineName != "" :
		# marking AUT as running, as we already checked the status of application under test
		msg = "AUT: Running"

		# generating post chaos event
		types.SetEngineEventAttributes(eventsDetails, types.PostChaosCheck, msg, "Normal", chaosDetails)
		events.GenerateEvents(eventsDetails, chaosDetails, "ChaosEngine", clients)
	

	#Updating the chaosResult in the end of experiment
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