
from kubernetes import client, config, dynamic
import time
from kubernetes.client.rest import ApiException
import logging
logger = logging.getLogger(__name__)
from chaosk8s import create_k8s_api_client
from kubernetes.client import api_client

from datetime import datetime

def deployment(clients, targetPod, chaosDetails):
	api = create_k8s_api_client(secrets = None)
	v1 = client.AppsV1Api(api)
	try:
		deployList = v1.list_namespaced_deployment(chaosDetails.AppDetail.Namespace, label_selector=chaosDetails.AppDetail.Label)
	except ApiException as e:
		return False, logger.error("no deployment found with matching label, err: %v", e) 
	
	for deploy in range(deployList):
		if deploy.ObjectMeta.Annotations[chaosDetails.AppDetail.AnnotationKey] == chaosDetails.AppDetail.AnnotationValue:
			rsOwnerRef = targetPod.OwnerReferences
			for own in range(rsOwnerRef) :
				if own.Kind == "ReplicaSet" :
					try:
						rs = v1.read_namespaced_replica_set(own.name, chaosDetails.AppDetail.Namespace)
					except Exception as e:
						return False, e
					
					ownerRef = rs.OwnerReferences
					for own in range(ownerRef):
						if own.Kind == "Deployment" & own.Name == deploy.Name:
							logger.info("[Info]: chaos candidate of kind: %v, name: %v, namespace: %v", chaosDetails.AppDetail.Kind, deploy.Name, deploy.Namespace)
							return True, None
						

def statefulset(clients, targetPod, chaosDetails):
	api = create_k8s_api_client(secrets = None)
	v1 = client.AppsV1Api(api)
	
	try:
		stsList = v1.list_namespaced_stateful_set(chaosDetails.AppDetail.Namespace, label_selector=chaosDetails.AppDetail.Label)
	except Exception as e:
		return False, e
	if len(stsList.items) == 0:
		return False, logger.error("no statefulset found with matching label")
	
	for sts in range(stsList.items):
		if sts.ObjectMeta.Annotations[chaosDetails.AppDetail.AnnotationKey] == chaosDetails.AppDetail.AnnotationValue :
			ownerRef = targetPod.OwnerReferences
			for own in range(ownerRef):
				if own.Kind == "StatefulSet" & own.Name == sts.Name:
					logger.info("[Info]: chaos candidate of kind: %v, name: %v, namespace: %v", chaosDetails.AppDetail.Kind, sts.Name, sts.Namespace)
					return True, None

def daemonset(clients, targetPod, chaosDetails):
	api = create_k8s_api_client(secrets = None)
	v1 = client.AppsV1Api(api)
	
	try:
		dsList = v1.list_namespaced_daemon_set(chaosDetails.AppDetail.Namespace, label_selector=chaosDetails.AppDetail.Label)
	except Exception as e:
		return False, e
	if len(dsList.items) == 0:
		return False, logger.error("no daemonset found with matching label")
	
	for ds in range(dsList.items):
		if ds.ObjectMeta.Annotations[chaosDetails.AppDetail.AnnotationKey] == chaosDetails.AppDetail.AnnotationValue:
			ownerRef = targetPod.OwnerReferences
			for own in range(ownerRef):
				if own.Kind == "DaemonSet" & own.Name == ds.Name:
					logger.info("[Info]: chaos candidate of kind: %v, name: %v, namespace: %v", chaosDetails.AppDetail.Kind, ds.Name, ds.Namespace)
					return True, None

def deploymentconfig(targetPod, chaosDetails):
	api = create_k8s_api_client(secrets = None)
	v1 = client.CoreV1Api(api)
	clientDyn = dynamic.DynamicClient(
        api_client.ApiClient(configuration=config.load_kube_config())
    )
	
	try:
		deploymentConfigList = clientDyn.resources.get(api_version="v1", kind="DeploymentConfig", group="apps.openshift.io", label_selector=chaosDetails.AppDetail.Label)
	except Exception as e:
		return False, e
	if None or len(deploymentConfigList.items) == 0:
		return False, logger.error("no deploymentconfig found with matching labels")
	
	for dc in range(deploymentConfigList.items):
		annotations = dc.GetAnnotations()
		if annotations[chaosDetails.AppDetail.AnnotationKey] == chaosDetails.AppDetail.AnnotationValue:
			rcOwnerRef = targetPod.OwnerReferences
			for own in range(rcOwnerRef):
				if own.Kind == "ReplicationController":
					try:
						rc = v1.read_namespaced_replication_controller(own.Name, chaosDetails.AppDetail.Namespace)
					except Exception as e:
						return False, e
					
					ownerRef = rc.OwnerReferences
					for own in range(ownerRef):
						if own.Kind == "DeploymentConfig" & own.Name == dc.GetName():
							logger.info("[Info]: chaos candidate of kind: %v, name: %v, namespace: %v", chaosDetails.AppDetail.Kind, dc.GetName(), dc.GetNamespace())
							return True, None


def rollout(clients, targetPod, chaosDetails):
	api = create_k8s_api_client(secrets = None)
	v1 = client.AppsV1beta1Api(api)
	clientDyn = dynamic.DynamicClient(
        api_client.ApiClient(configuration=config.load_kube_config())
    )
	
	try:
		rolloutList = clientDyn.resources.get(api_version="v1alpha1", kind="Rollout", group="argoproj.io", label_selector=chaosDetails.AppDetail.Label)
	except Exception as e:
		return False, e
	if len(rolloutList.items) == 0:
		return False, logger.error("no rollouts found with matching labels")
	
	for ro in rolloutList.items :
		annotations = ro.GetAnnotations()
		if annotations[chaosDetails.AppDetail.AnnotationKey] == chaosDetails.AppDetail.AnnotationValue:
			rsOwnerRef = targetPod.OwnerReferences
			for own in range(rsOwnerRef) :
				if own.Kind == "ReplicaSet":
					try:
						rs = v1.read_namespaced_replica_set(own.name, chaosDetails.AppDetail.Namespace)
					except Exception as e:
						return False, e
					
					ownerRef = rs.OwnerReferences
					for own in range(ownerRef):
						if own.Kind == "Rollout" & own.Name == ro.GetName():
							logger.info("[Info]: chaos candidate of kind: %v, name: %v, namespace: %v", chaosDetails.AppDetail.Kind, ro.GetName(), ro.GetNamespace())
							return True, None


def numbers_to_strings(argument, clients, targetPod,chaosDetails):
    switcher = {
        "deployment": deployment(clients, targetPod,chaosDetails),
        "statefulset": statefulset(clients, targetPod,chaosDetails),
        "daemonset": daemonset(clients, targetPod,chaosDetails),
		"deploymentconfig": deploymentconfig(clients, targetPod,chaosDetails),
		"rollout" : rollout(clients, targetPod,chaosDetails),
    }
    return switcher.get(argument, "%v appkind is not supported",chaosDetails.AppDetail.Kind)
	
# IsPodParentAnnotated check whether the target pod's parent is annotated or not
def IsPodParentAnnotated(clients, targetPod, chaosDetails):

    return numbers_to_strings(chaosDetails.AppDetail.Kind, clients, targetPod,chaosDetails)
