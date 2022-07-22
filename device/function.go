// -*- Mode: Go; indent-tabs-mode: t -*-
//
// Copyright (C) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

package device

type AddIPAddressFilterFunction struct{}

func (_ *AddIPAddressFilterFunction) Request() interface{} {
	return &AddIPAddressFilter{}
}
func (_ *AddIPAddressFilterFunction) Response() interface{} {
	return &AddIPAddressFilterResponse{}
}

type AddScopesFunction struct{}

func (_ *AddScopesFunction) Request() interface{} {
	return &AddScopes{}
}
func (_ *AddScopesFunction) Response() interface{} {
	return &AddScopesResponse{}
}

type CreateCertificateFunction struct{}

func (_ *CreateCertificateFunction) Request() interface{} {
	return &CreateCertificate{}
}
func (_ *CreateCertificateFunction) Response() interface{} {
	return &CreateCertificateResponse{}
}

type CreateDot1XConfigurationFunction struct{}

func (_ *CreateDot1XConfigurationFunction) Request() interface{} {
	return &CreateDot1XConfiguration{}
}
func (_ *CreateDot1XConfigurationFunction) Response() interface{} {
	return &CreateDot1XConfigurationResponse{}
}

type CreateStorageConfigurationFunction struct{}

func (_ *CreateStorageConfigurationFunction) Request() interface{} {
	return &CreateStorageConfiguration{}
}
func (_ *CreateStorageConfigurationFunction) Response() interface{} {
	return &CreateStorageConfigurationResponse{}
}

type CreateUsersFunction struct{}

func (_ *CreateUsersFunction) Request() interface{} {
	return &CreateUsers{}
}
func (_ *CreateUsersFunction) Response() interface{} {
	return &CreateUsersResponse{}
}

type DeleteCertificatesFunction struct{}

func (_ *DeleteCertificatesFunction) Request() interface{} {
	return &DeleteCertificates{}
}
func (_ *DeleteCertificatesFunction) Response() interface{} {
	return &DeleteCertificatesResponse{}
}

type DeleteDot1XConfigurationFunction struct{}

func (_ *DeleteDot1XConfigurationFunction) Request() interface{} {
	return &DeleteDot1XConfiguration{}
}
func (_ *DeleteDot1XConfigurationFunction) Response() interface{} {
	return &DeleteDot1XConfigurationResponse{}
}

type DeleteGeoLocationFunction struct{}

func (_ *DeleteGeoLocationFunction) Request() interface{} {
	return &DeleteGeoLocation{}
}
func (_ *DeleteGeoLocationFunction) Response() interface{} {
	return &DeleteGeoLocationResponse{}
}

type DeleteStorageConfigurationFunction struct{}

func (_ *DeleteStorageConfigurationFunction) Request() interface{} {
	return &DeleteStorageConfiguration{}
}
func (_ *DeleteStorageConfigurationFunction) Response() interface{} {
	return &DeleteStorageConfigurationResponse{}
}

type DeleteUsersFunction struct{}

func (_ *DeleteUsersFunction) Request() interface{} {
	return &DeleteUsers{}
}
func (_ *DeleteUsersFunction) Response() interface{} {
	return &DeleteUsersResponse{}
}

type GetAccessPolicyFunction struct{}

func (_ *GetAccessPolicyFunction) Request() interface{} {
	return &GetAccessPolicy{}
}
func (_ *GetAccessPolicyFunction) Response() interface{} {
	return &GetAccessPolicyResponse{}
}

type GetCACertificatesFunction struct{}

func (_ *GetCACertificatesFunction) Request() interface{} {
	return &GetCACertificates{}
}
func (_ *GetCACertificatesFunction) Response() interface{} {
	return &GetCACertificatesResponse{}
}

type GetCapabilitiesFunction struct{}

func (_ *GetCapabilitiesFunction) Request() interface{} {
	return &GetCapabilities{}
}
func (_ *GetCapabilitiesFunction) Response() interface{} {
	return &GetCapabilitiesResponse{}
}

type GetCertificateInformationFunction struct{}

func (_ *GetCertificateInformationFunction) Request() interface{} {
	return &GetCertificateInformation{}
}
func (_ *GetCertificateInformationFunction) Response() interface{} {
	return &GetCertificateInformationResponse{}
}

type GetCertificatesFunction struct{}

func (_ *GetCertificatesFunction) Request() interface{} {
	return &GetCertificates{}
}
func (_ *GetCertificatesFunction) Response() interface{} {
	return &GetCertificatesResponse{}
}

type GetCertificatesStatusFunction struct{}

func (_ *GetCertificatesStatusFunction) Request() interface{} {
	return &GetCertificatesStatus{}
}
func (_ *GetCertificatesStatusFunction) Response() interface{} {
	return &GetCertificatesStatusResponse{}
}

type GetClientCertificateModeFunction struct{}

func (_ *GetClientCertificateModeFunction) Request() interface{} {
	return &GetClientCertificateMode{}
}
func (_ *GetClientCertificateModeFunction) Response() interface{} {
	return &GetClientCertificateModeResponse{}
}

type GetDNSFunction struct{}

func (_ *GetDNSFunction) Request() interface{} {
	return &GetDNS{}
}
func (_ *GetDNSFunction) Response() interface{} {
	return &GetDNSResponse{}
}

type GetDPAddressesFunction struct{}

func (_ *GetDPAddressesFunction) Request() interface{} {
	return &GetDPAddresses{}
}
func (_ *GetDPAddressesFunction) Response() interface{} {
	return &GetDPAddressesResponse{}
}

type GetDeviceInformationFunction struct{}

func (_ *GetDeviceInformationFunction) Request() interface{} {
	return &GetDeviceInformation{}
}
func (_ *GetDeviceInformationFunction) Response() interface{} {
	return &GetDeviceInformationResponse{}
}

type GetDiscoveryModeFunction struct{}

func (_ *GetDiscoveryModeFunction) Request() interface{} {
	return &GetDiscoveryMode{}
}
func (_ *GetDiscoveryModeFunction) Response() interface{} {
	return &GetDiscoveryModeResponse{}
}

type GetDot11CapabilitiesFunction struct{}

func (_ *GetDot11CapabilitiesFunction) Request() interface{} {
	return &GetDot11Capabilities{}
}
func (_ *GetDot11CapabilitiesFunction) Response() interface{} {
	return &GetDot11CapabilitiesResponse{}
}

type GetDot11StatusFunction struct{}

func (_ *GetDot11StatusFunction) Request() interface{} {
	return &GetDot11Status{}
}
func (_ *GetDot11StatusFunction) Response() interface{} {
	return &GetDot11StatusResponse{}
}

type GetDot1XConfigurationFunction struct{}

func (_ *GetDot1XConfigurationFunction) Request() interface{} {
	return &GetDot1XConfiguration{}
}
func (_ *GetDot1XConfigurationFunction) Response() interface{} {
	return &GetDot1XConfigurationResponse{}
}

type GetDot1XConfigurationsFunction struct{}

func (_ *GetDot1XConfigurationsFunction) Request() interface{} {
	return &GetDot1XConfigurations{}
}
func (_ *GetDot1XConfigurationsFunction) Response() interface{} {
	return &GetDot1XConfigurationsResponse{}
}

type GetDynamicDNSFunction struct{}

func (_ *GetDynamicDNSFunction) Request() interface{} {
	return &GetDynamicDNS{}
}
func (_ *GetDynamicDNSFunction) Response() interface{} {
	return &GetDynamicDNSResponse{}
}

type GetEndpointReferenceFunction struct{}

func (_ *GetEndpointReferenceFunction) Request() interface{} {
	return &GetEndpointReference{}
}
func (_ *GetEndpointReferenceFunction) Response() interface{} {
	return &GetEndpointReferenceResponse{}
}

type GetGeoLocationFunction struct{}

func (_ *GetGeoLocationFunction) Request() interface{} {
	return &GetGeoLocation{}
}
func (_ *GetGeoLocationFunction) Response() interface{} {
	return &GetGeoLocationResponse{}
}

type GetHostnameFunction struct{}

func (_ *GetHostnameFunction) Request() interface{} {
	return &GetHostname{}
}
func (_ *GetHostnameFunction) Response() interface{} {
	return &GetHostnameResponse{}
}

type GetIPAddressFilterFunction struct{}

func (_ *GetIPAddressFilterFunction) Request() interface{} {
	return &GetIPAddressFilter{}
}
func (_ *GetIPAddressFilterFunction) Response() interface{} {
	return &GetIPAddressFilterResponse{}
}

type GetNTPFunction struct{}

func (_ *GetNTPFunction) Request() interface{} {
	return &GetNTP{}
}
func (_ *GetNTPFunction) Response() interface{} {
	return &GetNTPResponse{}
}

type GetNetworkDefaultGatewayFunction struct{}

func (_ *GetNetworkDefaultGatewayFunction) Request() interface{} {
	return &GetNetworkDefaultGateway{}
}
func (_ *GetNetworkDefaultGatewayFunction) Response() interface{} {
	return &GetNetworkDefaultGatewayResponse{}
}

type GetNetworkInterfacesFunction struct{}

func (_ *GetNetworkInterfacesFunction) Request() interface{} {
	return &GetNetworkInterfaces{}
}
func (_ *GetNetworkInterfacesFunction) Response() interface{} {
	return &GetNetworkInterfacesResponse{}
}

type GetNetworkProtocolsFunction struct{}

func (_ *GetNetworkProtocolsFunction) Request() interface{} {
	return &GetNetworkProtocols{}
}
func (_ *GetNetworkProtocolsFunction) Response() interface{} {
	return &GetNetworkProtocolsResponse{}
}

type GetPkcs10RequestFunction struct{}

func (_ *GetPkcs10RequestFunction) Request() interface{} {
	return &GetPkcs10Request{}
}
func (_ *GetPkcs10RequestFunction) Response() interface{} {
	return &GetPkcs10RequestResponse{}
}

type GetRelayOutputsFunction struct{}

func (_ *GetRelayOutputsFunction) Request() interface{} {
	return &GetRelayOutputs{}
}
func (_ *GetRelayOutputsFunction) Response() interface{} {
	return &GetRelayOutputsResponse{}
}

type GetRemoteDiscoveryModeFunction struct{}

func (_ *GetRemoteDiscoveryModeFunction) Request() interface{} {
	return &GetRemoteDiscoveryMode{}
}
func (_ *GetRemoteDiscoveryModeFunction) Response() interface{} {
	return &GetRemoteDiscoveryModeResponse{}
}

type GetRemoteUserFunction struct{}

func (_ *GetRemoteUserFunction) Request() interface{} {
	return &GetRemoteUser{}
}
func (_ *GetRemoteUserFunction) Response() interface{} {
	return &GetRemoteUserResponse{}
}

type GetScopesFunction struct{}

func (_ *GetScopesFunction) Request() interface{} {
	return &GetScopes{}
}
func (_ *GetScopesFunction) Response() interface{} {
	return &GetScopesResponse{}
}

type GetServiceCapabilitiesFunction struct{}

func (_ *GetServiceCapabilitiesFunction) Request() interface{} {
	return &GetServiceCapabilities{}
}
func (_ *GetServiceCapabilitiesFunction) Response() interface{} {
	return &GetServiceCapabilitiesResponse{}
}

type GetServicesFunction struct{}

func (_ *GetServicesFunction) Request() interface{} {
	return &GetServices{}
}
func (_ *GetServicesFunction) Response() interface{} {
	return &GetServicesResponse{}
}

type GetStorageConfigurationFunction struct{}

func (_ *GetStorageConfigurationFunction) Request() interface{} {
	return &GetStorageConfiguration{}
}
func (_ *GetStorageConfigurationFunction) Response() interface{} {
	return &GetStorageConfigurationResponse{}
}

type GetStorageConfigurationsFunction struct{}

func (_ *GetStorageConfigurationsFunction) Request() interface{} {
	return &GetStorageConfigurations{}
}
func (_ *GetStorageConfigurationsFunction) Response() interface{} {
	return &GetStorageConfigurationsResponse{}
}

type GetSystemBackupFunction struct{}

func (_ *GetSystemBackupFunction) Request() interface{} {
	return &GetSystemBackup{}
}
func (_ *GetSystemBackupFunction) Response() interface{} {
	return &GetSystemBackupResponse{}
}

type GetSystemDateAndTimeFunction struct{}

func (_ *GetSystemDateAndTimeFunction) Request() interface{} {
	return &GetSystemDateAndTime{}
}
func (_ *GetSystemDateAndTimeFunction) Response() interface{} {
	return &GetSystemDateAndTimeResponse{}
}

type GetSystemLogFunction struct{}

func (_ *GetSystemLogFunction) Request() interface{} {
	return &GetSystemLog{}
}
func (_ *GetSystemLogFunction) Response() interface{} {
	return &GetSystemLogResponse{}
}

type GetSystemSupportInformationFunction struct{}

func (_ *GetSystemSupportInformationFunction) Request() interface{} {
	return &GetSystemSupportInformation{}
}
func (_ *GetSystemSupportInformationFunction) Response() interface{} {
	return &GetSystemSupportInformationResponse{}
}

type GetSystemUrisFunction struct{}

func (_ *GetSystemUrisFunction) Request() interface{} {
	return &GetSystemUris{}
}
func (_ *GetSystemUrisFunction) Response() interface{} {
	return &GetSystemUrisResponse{}
}

type GetUsersFunction struct{}

func (_ *GetUsersFunction) Request() interface{} {
	return &GetUsers{}
}
func (_ *GetUsersFunction) Response() interface{} {
	return &GetUsersResponse{}
}

type GetWsdlUrlFunction struct{}

func (_ *GetWsdlUrlFunction) Request() interface{} {
	return &GetWsdlUrl{}
}
func (_ *GetWsdlUrlFunction) Response() interface{} {
	return &GetWsdlUrlResponse{}
}

type GetZeroConfigurationFunction struct{}

func (_ *GetZeroConfigurationFunction) Request() interface{} {
	return &GetZeroConfiguration{}
}
func (_ *GetZeroConfigurationFunction) Response() interface{} {
	return &GetZeroConfigurationResponse{}
}

type LoadCACertificatesFunction struct{}

func (_ *LoadCACertificatesFunction) Request() interface{} {
	return &LoadCACertificates{}
}
func (_ *LoadCACertificatesFunction) Response() interface{} {
	return &LoadCACertificatesResponse{}
}

type LoadCertificateWithPrivateKeyFunction struct{}

func (_ *LoadCertificateWithPrivateKeyFunction) Request() interface{} {
	return &LoadCertificateWithPrivateKey{}
}
func (_ *LoadCertificateWithPrivateKeyFunction) Response() interface{} {
	return &LoadCertificateWithPrivateKeyResponse{}
}

type LoadCertificatesFunction struct{}

func (_ *LoadCertificatesFunction) Request() interface{} {
	return &LoadCertificates{}
}
func (_ *LoadCertificatesFunction) Response() interface{} {
	return &LoadCertificatesResponse{}
}

type RemoveIPAddressFilterFunction struct{}

func (_ *RemoveIPAddressFilterFunction) Request() interface{} {
	return &RemoveIPAddressFilter{}
}
func (_ *RemoveIPAddressFilterFunction) Response() interface{} {
	return &RemoveIPAddressFilterResponse{}
}

type RemoveScopesFunction struct{}

func (_ *RemoveScopesFunction) Request() interface{} {
	return &RemoveScopes{}
}
func (_ *RemoveScopesFunction) Response() interface{} {
	return &RemoveScopesResponse{}
}

type RestoreSystemFunction struct{}

func (_ *RestoreSystemFunction) Request() interface{} {
	return &RestoreSystem{}
}
func (_ *RestoreSystemFunction) Response() interface{} {
	return &RestoreSystemResponse{}
}

type ScanAvailableDot11NetworksFunction struct{}

func (_ *ScanAvailableDot11NetworksFunction) Request() interface{} {
	return &ScanAvailableDot11Networks{}
}
func (_ *ScanAvailableDot11NetworksFunction) Response() interface{} {
	return &ScanAvailableDot11NetworksResponse{}
}

type SendAuxiliaryCommandFunction struct{}

func (_ *SendAuxiliaryCommandFunction) Request() interface{} {
	return &SendAuxiliaryCommand{}
}
func (_ *SendAuxiliaryCommandFunction) Response() interface{} {
	return &SendAuxiliaryCommandResponse{}
}

type SetAccessPolicyFunction struct{}

func (_ *SetAccessPolicyFunction) Request() interface{} {
	return &SetAccessPolicy{}
}
func (_ *SetAccessPolicyFunction) Response() interface{} {
	return &SetAccessPolicyResponse{}
}

type SetCertificatesStatusFunction struct{}

func (_ *SetCertificatesStatusFunction) Request() interface{} {
	return &SetCertificatesStatus{}
}
func (_ *SetCertificatesStatusFunction) Response() interface{} {
	return &SetCertificatesStatusResponse{}
}

type SetClientCertificateModeFunction struct{}

func (_ *SetClientCertificateModeFunction) Request() interface{} {
	return &SetClientCertificateMode{}
}
func (_ *SetClientCertificateModeFunction) Response() interface{} {
	return &SetClientCertificateModeResponse{}
}

type SetDNSFunction struct{}

func (_ *SetDNSFunction) Request() interface{} {
	return &SetDNS{}
}
func (_ *SetDNSFunction) Response() interface{} {
	return &SetDNSResponse{}
}

type SetDPAddressesFunction struct{}

func (_ *SetDPAddressesFunction) Request() interface{} {
	return &SetDPAddresses{}
}
func (_ *SetDPAddressesFunction) Response() interface{} {
	return &SetDPAddressesResponse{}
}

type SetDiscoveryModeFunction struct{}

func (_ *SetDiscoveryModeFunction) Request() interface{} {
	return &SetDiscoveryMode{}
}
func (_ *SetDiscoveryModeFunction) Response() interface{} {
	return &SetDiscoveryModeResponse{}
}

type SetDot1XConfigurationFunction struct{}

func (_ *SetDot1XConfigurationFunction) Request() interface{} {
	return &SetDot1XConfiguration{}
}
func (_ *SetDot1XConfigurationFunction) Response() interface{} {
	return &SetDot1XConfigurationResponse{}
}

type SetDynamicDNSFunction struct{}

func (_ *SetDynamicDNSFunction) Request() interface{} {
	return &SetDynamicDNS{}
}
func (_ *SetDynamicDNSFunction) Response() interface{} {
	return &SetDynamicDNSResponse{}
}

type SetGeoLocationFunction struct{}

func (_ *SetGeoLocationFunction) Request() interface{} {
	return &SetGeoLocation{}
}
func (_ *SetGeoLocationFunction) Response() interface{} {
	return &SetGeoLocationResponse{}
}

type SetHostnameFunction struct{}

func (_ *SetHostnameFunction) Request() interface{} {
	return &SetHostname{}
}
func (_ *SetHostnameFunction) Response() interface{} {
	return &SetHostnameResponse{}
}

type SetHostnameFromDHCPFunction struct{}

func (_ *SetHostnameFromDHCPFunction) Request() interface{} {
	return &SetHostnameFromDHCP{}
}
func (_ *SetHostnameFromDHCPFunction) Response() interface{} {
	return &SetHostnameFromDHCPResponse{}
}

type SetIPAddressFilterFunction struct{}

func (_ *SetIPAddressFilterFunction) Request() interface{} {
	return &SetIPAddressFilter{}
}
func (_ *SetIPAddressFilterFunction) Response() interface{} {
	return &SetIPAddressFilterResponse{}
}

type SetNTPFunction struct{}

func (_ *SetNTPFunction) Request() interface{} {
	return &SetNTP{}
}
func (_ *SetNTPFunction) Response() interface{} {
	return &SetNTPResponse{}
}

type SetNetworkDefaultGatewayFunction struct{}

func (_ *SetNetworkDefaultGatewayFunction) Request() interface{} {
	return &SetNetworkDefaultGateway{}
}
func (_ *SetNetworkDefaultGatewayFunction) Response() interface{} {
	return &SetNetworkDefaultGatewayResponse{}
}

type SetNetworkInterfacesFunction struct{}

func (_ *SetNetworkInterfacesFunction) Request() interface{} {
	return &SetNetworkInterfaces{}
}
func (_ *SetNetworkInterfacesFunction) Response() interface{} {
	return &SetNetworkInterfacesResponse{}
}

type SetNetworkProtocolsFunction struct{}

func (_ *SetNetworkProtocolsFunction) Request() interface{} {
	return &SetNetworkProtocols{}
}
func (_ *SetNetworkProtocolsFunction) Response() interface{} {
	return &SetNetworkProtocolsResponse{}
}

type SetRelayOutputSettingsFunction struct{}

func (_ *SetRelayOutputSettingsFunction) Request() interface{} {
	return &SetRelayOutputSettings{}
}
func (_ *SetRelayOutputSettingsFunction) Response() interface{} {
	return &SetRelayOutputSettingsResponse{}
}

type SetRelayOutputStateFunction struct{}

func (_ *SetRelayOutputStateFunction) Request() interface{} {
	return &SetRelayOutputState{}
}
func (_ *SetRelayOutputStateFunction) Response() interface{} {
	return &SetRelayOutputStateResponse{}
}

type SetRemoteDiscoveryModeFunction struct{}

func (_ *SetRemoteDiscoveryModeFunction) Request() interface{} {
	return &SetRemoteDiscoveryMode{}
}
func (_ *SetRemoteDiscoveryModeFunction) Response() interface{} {
	return &SetRemoteDiscoveryModeResponse{}
}

type SetRemoteUserFunction struct{}

func (_ *SetRemoteUserFunction) Request() interface{} {
	return &SetRemoteUser{}
}
func (_ *SetRemoteUserFunction) Response() interface{} {
	return &SetRemoteUserResponse{}
}

type SetScopesFunction struct{}

func (_ *SetScopesFunction) Request() interface{} {
	return &SetScopes{}
}
func (_ *SetScopesFunction) Response() interface{} {
	return &SetScopesResponse{}
}

type SetStorageConfigurationFunction struct{}

func (_ *SetStorageConfigurationFunction) Request() interface{} {
	return &SetStorageConfiguration{}
}
func (_ *SetStorageConfigurationFunction) Response() interface{} {
	return &SetStorageConfigurationResponse{}
}

type SetSystemDateAndTimeFunction struct{}

func (_ *SetSystemDateAndTimeFunction) Request() interface{} {
	return &SetSystemDateAndTime{}
}
func (_ *SetSystemDateAndTimeFunction) Response() interface{} {
	return &SetSystemDateAndTimeResponse{}
}

type SetSystemFactoryDefaultFunction struct{}

func (_ *SetSystemFactoryDefaultFunction) Request() interface{} {
	return &SetSystemFactoryDefault{}
}
func (_ *SetSystemFactoryDefaultFunction) Response() interface{} {
	return &SetSystemFactoryDefaultResponse{}
}

type SetUserFunction struct{}

func (_ *SetUserFunction) Request() interface{} {
	return &SetUser{}
}
func (_ *SetUserFunction) Response() interface{} {
	return &SetUserResponse{}
}

type SetZeroConfigurationFunction struct{}

func (_ *SetZeroConfigurationFunction) Request() interface{} {
	return &SetZeroConfiguration{}
}
func (_ *SetZeroConfigurationFunction) Response() interface{} {
	return &SetZeroConfigurationResponse{}
}

type StartFirmwareUpgradeFunction struct{}

func (_ *StartFirmwareUpgradeFunction) Request() interface{} {
	return &StartFirmwareUpgrade{}
}
func (_ *StartFirmwareUpgradeFunction) Response() interface{} {
	return &StartFirmwareUpgradeResponse{}
}

type StartSystemRestoreFunction struct{}

func (_ *StartSystemRestoreFunction) Request() interface{} {
	return &StartSystemRestore{}
}
func (_ *StartSystemRestoreFunction) Response() interface{} {
	return &StartSystemRestoreResponse{}
}

type SystemRebootFunction struct{}

func (_ *SystemRebootFunction) Request() interface{} {
	return &SystemReboot{}
}
func (_ *SystemRebootFunction) Response() interface{} {
	return &SystemRebootResponse{}
}

type UpgradeSystemFirmwareFunction struct{}

func (_ *UpgradeSystemFirmwareFunction) Request() interface{} {
	return &UpgradeSystemFirmware{}
}
func (_ *UpgradeSystemFirmwareFunction) Response() interface{} {
	return &UpgradeSystemFirmwareResponse{}
}

type GetEndpointReferenceFunction struct{}

func (function *GetEndpointReferenceFunction) Request() interface{} {
	return &GetEndpointReference{}
}

func (function *GetEndpointReferenceFunction) Response() interface{} {
	return &GetEndpointReferenceResponse{}
}
