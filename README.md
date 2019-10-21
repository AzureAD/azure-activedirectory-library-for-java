# Microsoft Azure Active Directory Authentication Library (ADAL) for Java

`master` branch    | `dev` branch    | Reference Docs
--------------------|-----------------|---------------
[![Build Status](https://identitydivision.visualstudio.com/_apis/public/build/definitions/a7934fdd-dcde-4492-a406-7fad6ac00e17/591/badge?branchName=master)](https://identitydivision.visualstudio.com/IDDP/IDDP%20Team/_build/index?definitionId=591) | [![Build Status](https://identitydivision.visualstudio.com/_apis/public/build/definitions/a7934fdd-dcde-4492-a406-7fad6ac00e17/591/badge?branchName=dev)](https://identitydivision.visualstudio.com/IDDP/IDDP%20Team/_build/index?definitionId=591) | [![Javadocs](http://javadoc.io/badge/com.microsoft.azure/adal4j.svg)](http://javadoc.io/doc/com.microsoft.azure/adal4j)

|[Getting Started](https://github.com/AzureAD/azure-activedirectory-library-for-java/wiki)| [Docs](https://aka.ms/aaddev)| [Samples](https://github.com/AzureAD/azure-activedirectory-library-for-java/wiki/Code-samples)| [Support](README.md#community-help-and-support)
| --- | --- | --- | --- |

The ADAL for Java library enables Java applications to authenticate with Azure AD and get tokens to access Azure AD protected web resources.

## Update to MSAL4J now!

[MSAL4J](https://github.com/AzureAD/microsoft-authentication-library-for-java) is the new authentication library to be used with the Microsoft identity platform.

Building on top of ADAL, MSAL works with both the [Open ID Connect certified Azure AD V2 endpoint](https://docs.microsoft.com/en-us/azure/active-directory/develop/about-microsoft-identity-platform) and the new social identity solution from Microsoft, Azure AD B2C.

ADAL4J is in maintenance mode and no new features will be added going forward except for security fixes. All our ongoing efforts will be focused on improving [MSAL4J](https://github.com/AzureAD/microsoft-authentication-library-for-java). 

## Installation and usage

You can find the steps for installation and basic usage documented in the [ADAL4J Basics Wiki](https://github.com/AzureAD/azure-activedirectory-library-for-java/wiki/ADAL4J-Basics).

## Versions
Current version - 1.6.4

Minimum recommended version - 1.6.4

From version 1.3.0 support for handling Conditional Access claims challenge was added. You can read about CA [here](https://go.microsoft.com/fwlink/?linkid=855860) and refer this [sample](https://github.com/AzureAD/azure-activedirectory-library-for-java/tree/dev/src/samples/web-app-samples-for-adal4j) to handle it.

You can find the changes for each version in the [change log](https://github.com/AzureAD/azure-activedirectory-library-for-java/blob/master/changelog.txt).

## Contribution
All code is licensed under the MIT License and we triage actively on GitHub. We encourage and welcome contributions to the library. Please read the [contributing guide](./contributing.md) before starting.

## Build and Run

Refer [this page](https://github.com/AzureAD/azure-activedirectory-library-for-java/wiki/Maven) for information on building the project and running tests.

## Samples and Documentation

Refer these [code samples](https://github.com/AzureAD/azure-activedirectory-library-for-java/wiki/Code-samples) using ADAL4J in some basic scenarios.

We also provide a [full suite of sample applications](https://github.com/Azure-Samples) and [documentation](https://aka.ms/aaddev) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, macOS, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features.

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before.

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## We Value and Adhere to the Microsoft Open Source Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
