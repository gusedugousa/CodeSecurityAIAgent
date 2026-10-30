// Placeholder Bicep for a future Azure Container Apps deployment of the platform.
// Not wired into any deployment pipeline yet — documents the intended shape only.
// See infra/azure/README.md and docs/extension_points.md.

param location string = resourceGroup().location
param containerAppName string = 'governed-ai-code-security'
param containerImage string = 'REPLACE_ME.azurecr.io/governed-ai-code-security:latest'
param databaseUrlSecretName string = 'database-url'
param minReplicas int = 1
param maxReplicas int = 3

resource containerAppEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: '${containerAppName}-env'
  location: location
  properties: {}
}

resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: containerAppName
  location: location
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
      }
      secrets: [
        {
          name: databaseUrlSecretName
          value: 'REPLACE_ME'
        }
      ]
    }
    template: {
      containers: [
        {
          name: containerAppName
          image: containerImage
          env: [
            {
              name: 'APP_DATABASE_URL'
              secretRef: databaseUrlSecretName
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
      }
    }
  }
}
