module github.com/cilium/clustermesh-apiserver

go 1.14

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	k8s.io/client-go => github.com/cilium/client-go v0.0.0-20200917084247-85ed8d558b9c
)

require (
	github.com/cilium/cilium v1.9.0-rc1.0.20201021102837-f8de9896811c
	github.com/envoyproxy/protoc-gen-validate v0.3.0-java // indirect
	github.com/google/gops v0.3.10
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.6.1
	golang.org/x/sys v0.0.0-20200806125547-5acd03effb82
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v1.5.1
)
