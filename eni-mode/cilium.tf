locals {
  cilium_service_account = "cilium-operator"
}


resource "aws_iam_policy" "cilium" {
  description = "IAM policy for Cilium Operator"
  name_prefix = format("%s-%s-", local.name, "cilium-operator")
  path = "/"
  policy = data.aws_iam_policy_document.cilium.json
}

data "aws_iam_policy_document" "cilium" {
  statement {
    sid    = "CiliumOperator"
      effect = "Allow"
      actions = [
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs",
        "ec2:DescribeSecurityGroups",
        "ec2:CreateNetworkInterface",
        "ec2:AttachNetworkInterface",
        "ec2:ModifyNetworkInterfaceAttribute",
        "ec2:AssignPrivateIpAddresses",
        "ec2:CreateTags",
        "ec2:UnassignPrivateIpAddresses",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeInstanceTypes"
      ]
      resources = ["*"]
  }
}

resource "null_resource" "delete_aws_cni" {
  provisioner "local-exec" {
    command = "curl -s -k -XDELETE -H 'Authorization: Bearer ${data.aws_eks_cluster_auth.this.token}' -H 'Accept: application/json' -H 'Content-Type: application/json' '${module.eks.cluster_endpoint}/apis/apps/v1/namespaces/kube-system/daemonsets/aws-node'"
  }
}

resource "null_resource" "delete_kube_proxy" {
  provisioner "local-exec" {
    command = "curl -s -k -XDELETE -H 'Authorization: Bearer ${data.aws_eks_cluster_auth.this.token}' -H 'Accept: application/json' -H 'Content-Type: application/json' '${module.eks.cluster_endpoint}/apis/apps/v1/namespaces/kube-system/daemonsets/kube-proxy'"
  }
}

resource "kubernetes_config_map" "cni_config" {
  metadata {
    name      = "cni-configuration"
    namespace = "kube-system"
  }
  data = {
    "cni-config" = <<EOF
{
  "cniVersion":"0.3.1",
  "name":"cilium",
  "plugins": [
    {
      "cniVersion":"0.3.1",
      "type":"cilium-cni",
      "eni": {
        "first-interface-index": 1,
        "subnet-tags":{
          "Usage":"pods"
        }        
      }
    }
  ]
}
EOF
  }
}

module "cilium" {
  source         = "aws-ia/eks-blueprints-addon/aws"
  version        = "~> 1.0"

  chart            = "cilium"
  chart_version    = "1.15.6"
  repository       = "https://helm.cilium.io/"
  description      = "Cilium Networking for Kubernetes in ENI Mode"
  namespace        = "kube-system"
  create_namespace = false

  values = [templatefile("${path.module}/helm-values/cilium-values.yaml", {
    k8sServiceHost = try(element(split("://", module.eks.cluster_endpoint), 1), "")
  })]

  create_release = true
  create_role    = true
  create_policy  = false
  role_name      = format("%s-%s", local.name, "cilium-operator")
  role_policies  = { cilium_policy = aws_iam_policy.cilium.arn }

  oidc_providers = {
    this = {
      provider_arn    = module.eks.oidc_provider_arn
      # namespace       = "local.amp_namespace"
      service_account = local.cilium_service_account
    }
  }
  
  depends_on = [
    module.eks,
    null_resource.delete_aws_cni,
    null_resource.delete_kube_proxy,
    kubernetes_config_map.cni_config 
  ]
  
  tags = local.tags

}