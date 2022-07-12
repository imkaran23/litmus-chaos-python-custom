
import os
import pkg.types.types as types
import pkg.maths.maths as maths

#GetENV fetches all the env variables from the runner pod
def GetENV(experimentDetails):
    experimentDetails.ExperimentName =  os.getenv("EXPERIMENT_NAME", "custom-experiment")
    experimentDetails.ChaosNamespace = os.getenv("CHAOS_NAMESPACE", "litmus")
    experimentDetails.EngineName = os.getenv("CHAOSENGINE", "")
    experimentDetails.ChaosDuration = maths.atoi(os.getenv("TOTAL_CHAOS_DURATION", "30"))
    experimentDetails.ChaosInterval = os.getenv("CHAOS_INTERVAL", "10")
    experimentDetails.RampTime = maths.atoi(os.getenv("RAMP_TIME", "0"))
    experimentDetails.ChaosLib = os.getenv("LIB", "litmus")
    experimentDetails.AppNS = os.getenv("APP_NAMESPACE", "")
    experimentDetails.AppLabel = os.getenv("APP_LABEL", "")
    experimentDetails.AppKind = os.getenv("APP_KIND", "")
    experimentDetails.ChaosUID = os.getenv("CHAOS_UID", "")
    experimentDetails.InstanceID = os.getenv("INSTANCE_ID", "")
    experimentDetails.ChaosPodName = os.getenv("POD_NAME", "")
    experimentDetails.Force = (os.getenv("FORCE", "false") == 'true')
    experimentDetails.Delay = maths.atoi(os.getenv("STATUS_CHECK_DELAY", "2"))
    experimentDetails.Timeout = maths.atoi(os.getenv("STATUS_CHECK_TIMEOUT", "180"))
    experimentDetails.TargetPods = os.getenv("TARGET_PODS", "nginx")
    experimentDetails.PodsAffectedPerc = maths.atoi(os.getenv("PODS_AFFECTED_PERC", "0"))
    experimentDetails.Sequence = os.getenv("SEQUENCE", "parallel")
    experimentDetails.TargetContainer = os.getenv("TARGET_CONTAINER", "")
    experimentDetails.ChaosInjectCmd = os.getenv("CHAOS_INJECT_COMMAND", "")
    experimentDetails.ChaosKillCmd = os.getenv("CHAOS_KILL_COMMAND", "")
    experimentDetails.MongoAtlasSecretPath = os.getenv("MONGO_ATLAS_SECRET_PATH", "")
    experimentDetails.MongoAtlasSecretTransitPath = os.getenv("MONGO_ATLAS_SECRET_TRANSIT_PATH", "")
    experimentDetails.MongoAtlasURL = os.getenv("MONGO_ATLAS_CLUSTER_URL", "")
    experimentDetails.MongoAtlasPublicKey = os.getenv("MONGO_CLUSTER_PUBLIC_KEY", "")
    experimentDetails.MongoAtlasPrivateKey = os.getenv("MONGO_CLUSTER_PRIVATE_KEY", "")
    experimentDetails.KafkaClusterARN = os.getenv("KAFKA_CLUSTER_ARN", "")
    experimentDetails.KafkaAwsRegion = os.getenv("KAFKA_AWS_REGION", "")
    experimentDetails.KafkaSecretPath = os.getenv("KAFKA_SECRET_PATH", "")
    experimentDetails.KafkaTransitPath = os.getenv("KAFKA_SECRET_TRANSIT_PATH", "")
    experimentDetails.RedisSecretPath = os.getenv("ELASTIC_CACHE_SECRET_PATH", "")
    experimentDetails.RedisSecretTransit = os.getenv("ELASTIC_CACHE_SECRET_TRANSIT_PATH", "")
    experimentDetails.RedisAwsRegion = os.getenv("ELASTIC_CACHE_AWS_REGION", "")
    experimentDetails.RedisReplicationGroupId = os.getenv("ELASTIC_CACHE_REPLICATION_GROUP_ID", "")
    experimentDetails.RedisNodeGroupId = os.getenv("ELASTIC_CACHE_NODE_GROUP_ID", "")
    experimentDetails.Experiment = os.getenv("CUSTOM_EXPERIMENT_NAME", "ATLAS")
    experimentDetails.VaultURL = os.getenv("VAULT_URL", "")
    experimentDetails.VaultToken = os.getenv("VAULT_TOKEN", "")
    experimentDetails.AWSRoleARN = os.getenv("AWS_ROLE_ARN", "")
    experimentDetails.AWSWebIdentityTokenFile = os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
    experimentDetails.AWSAccessKeyId = os.getenv("AWS_ACCESS_KEY_ID", "")
    experimentDetails.AWSSecretAccessKey = os.getenv("AWS_SECRET_ACCESS_KEY", "")

#InitialiseChaosVariables initialise all the global variables
def InitialiseChaosVariables(chaosDetails, experimentDetails):
    appDetails = types.AppDetails()
    appDetails.AnnotationCheck = (os.getenv("ANNOTATION_CHECK", "false") == 'true')
    appDetails.AnnotationKey = os.getenv("ANNOTATION_KEY", "litmuschaos.io/chaos")
    appDetails.AnnotationValue = "true"
    appDetails.Kind = experimentDetails.AppKind
    appDetails.Label = experimentDetails.AppLabel
    appDetails.Namespace = experimentDetails.AppNS

    chaosDetails.ChaosNamespace = experimentDetails.ChaosNamespace
    chaosDetails.ChaosPodName = experimentDetails.ChaosPodName
    chaosDetails.ChaosUID = experimentDetails.ChaosUID
    chaosDetails.EngineName = experimentDetails.EngineName
    chaosDetails.ExperimentName = experimentDetails.ExperimentName
    chaosDetails.InstanceID = experimentDetails.InstanceID
    chaosDetails.Timeout = experimentDetails.Timeout
    chaosDetails.Delay = experimentDetails.Delay
    chaosDetails.AppDetail = appDetails
    chaosDetails.Randomness = (os.getenv("RANDOMNESS", "false") == 'true')
