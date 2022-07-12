# ExperimentDetails is for collecting all the experiment-related details
class ExperimentDetails(object):
    def __init__(self, ExperimentName=None, EngineName=None, ChaosDuration=None, ChaosInterval=None, RampTime=None,
                 Force=None, ChaosLib=None,
                 ChaosServiceAccount=None, AppNS=None, AppLabel=None, ChaosInjectCmd=None, AppKind=None,
                 InstanceID=None, ChaosNamespace=None, ChaosPodName=None, Timeout=None,
                 Delay=None, TargetPods=None, PodsAffectedPerc=None, ChaosKillCmd=None, Sequence=None,
                 LIBImagePullPolicy=None, TargetContainer=None, UID=None, MongoAtlasSecretPath=None,
                 MongoAtlasSecretTransitPath=None, MongoAtlasURL=None, MongoAtlasPublicKey=None,
                 MongoAtlasPrivateKey=None, KafkaClusterARN=None, KafkaAwsRegion=None, KafkaSecretPath=None,
                 KafkaTransitPath=None,
                 RedisSecretPath=None, RedisSecretTransit=None, RedisAwsRegion=None, RedisReplicationGroupId=None,
                 RedisNodeGroupId=None, Experiment=None, VaultURL=None, VaultToken=None, AWSRoleARN=None, AWSWebIdentityTokenFile=None,
                 AWSAccessKeyId=None, AWSSecretAccessKey=None
                 ):
        self.ExperimentName = ExperimentName
        self.EngineName = EngineName
        self.ChaosDuration = ChaosDuration
        self.ChaosInterval = ChaosInterval
        self.RampTime = RampTime
        self.ChaosLib = ChaosLib
        self.AppNS = AppNS
        self.AppLabel = AppLabel
        self.AppKind = AppKind
        self.InstanceID = InstanceID
        self.ChaosUID = UID
        self.ChaosNamespace = ChaosNamespace
        self.ChaosPodName = ChaosPodName
        self.Timeout = Timeout
        self.Delay = Delay
        self.TargetPods = TargetPods
        self.PodsAffectedPerc = PodsAffectedPerc
        self.LIBImagePullPolicy = LIBImagePullPolicy
        self.ChaosInjectCmd = ChaosInjectCmd
        self.ChaosKillCmd = ChaosKillCmd
        self.TargetContainer = TargetContainer
        
        self.MongoAtlasSecretPath = MongoAtlasSecretPath
        self.MongoAtlasSecretTransitPath = MongoAtlasSecretTransitPath
        self.MongoAtlasURL = MongoAtlasURL
        self.MongoAtlasPublicKey = MongoAtlasPublicKey
        self.MongoAtlasPrivateKey = MongoAtlasPrivateKey
        self.KafkaClusterARN = KafkaClusterARN
        self.KafkaAwsRegion = KafkaAwsRegion
        self.KafkaSecretPath = KafkaSecretPath
        self.KafkaTransitPath = KafkaTransitPath
        self.RedisSecretPath = RedisSecretPath
        self.RedisSecretTransit = RedisSecretTransit
        self.RedisAwsRegion = RedisAwsRegion
        self.RedisReplicationGroupId = RedisReplicationGroupId
        self.RedisNodeGroupId = RedisNodeGroupId
        self.Experiment = Experiment
        self.VaultURL = VaultURL
        self.VaultToken = VaultToken
        self.AWSRoleARN = AWSRoleARN
        self.AWSWebIdentityTokenFile = AWSWebIdentityTokenFile
        self.AWSAccessKeyId = AWSAccessKeyId
        self.AWSSecretAccessKey = AWSSecretAccessKey
