# MicrosoftSentinel-GreatHorn

## Overview

This repository contains Python code to be run as a Microsoft Function App
to integrate ingestion of GreatHorn event data to Microsoft Sentinel.

GreatHorn is a cloud-native email security solution that mitigates the 
risk of business email compromise across Microsoft 365 and Google Workspace.

## Configuration

This function only requires a valid GreatHorn API token. 

To create an API token:
* Log in to your [GreatHorn Dashboard](https://dashboard.greathorn.com/index.html) 
and click Settings (located in the top right corner).
* Select API Keys and then click Create API Key.
* Optionally,
  * Click Edit to change the name of the API key.
  * Click the edit icon to specify any IP restrictions.
* To view the key, click the eye icon in the Key column. Copy the key and store it somewhere safe.

## Events

This function app currently retrieves audit and policy events from GreatHorn. 
These events can be found the following tables:
* GreatHornPolicy_CL
* GreatHornAudit_CL

## Deploy to Azure

Use the following Deploy to Azure buttons to deploy the latest version of the function app:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fh0ffayyy%2FMicrosoftSentinel-GreatHorn%2Fmaster%2Fazuredeploy.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fh0ffayyy%2FMicrosoftSentinel-GreatHorn%2Fmaster%2Fazuredeploy.json)

This template deploys the following resources:
* An Azure function
* An Azure Storage Account
* A Key Vault