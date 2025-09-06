// finlythub_deploy.bicep

@description('Deployment location; the script passes this in.')
param location string = resourceGroup().location

@description('Name for the FinlytHub storage account (must be globally unique).')
param hubName string = 'finlythub'

@description('SKU for the storage account.')
param storageSku string = 'Standard_LRS'

@description('Tags (the script passes {"Application":"FinlytHub"}).')
param tags object = {
  Application: 'FinlytHub'
}

@description('Name of the user-assigned managed identity used by FinlytHub ops.')
param miName string = '${hubName}-mi'

@description('Optional timestamp injected by deployment script (not used by resources).')
@allowed([
  ''
])
param deploymentTimestamp string = ''

// ----------------- Storage (FinlytHub) -----------------
resource storageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: hubName
  location: location
  sku: {
    name: storageSku
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
  }
  tags: tags
}

@description('Blob service')
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2022-09-01' = {
  name: 'default'
  parent: storageAccount
}

resource dailyContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-09-01' = {
  name: 'daily'
  parent: blobService
  properties: { publicAccess: 'None' }
}

resource monthlyContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-09-01' = {
  name: 'monthly'
  parent: blobService
  properties: { publicAccess: 'None' }
}

resource reservationContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-09-01' = {
  name: 'reservation'
  parent: blobService
  properties: { publicAccess: 'None' }
}

// ----------------- User-Assigned Managed Identity -----------------
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: miName
  location: location
  tags: tags
}

// ----------------- Outputs -----------------
output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name
output dailyContainerName string = dailyContainer.name
output monthlyContainerName string = monthlyContainer.name
output reservationContainerName string = reservationContainer.name

// UAMI outputs used by the deploy script for RBAC
output uamiId string = uami.id
output uamiPrincipalId string = uami.properties.principalId
output uamiClientId string = uami.properties.clientId

// Echo the optional deployment timestamp (for traceability / silences unused param warning)
output deploymentTimestampOut string = deploymentTimestamp
