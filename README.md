[![Javadocs](http://javadoc.io/badge/com.microsoft.azure/adal4j.svg)](http://javadoc.io/doc/com.microsoft.azure/adal4j)
</br>
# Microsoft Azure Active Directory Authentication Library (ADAL) for Java
=====================================

## Samples and Documentation

[We provide a full suite of sample applications and documentation on GitHub](https://github.com/Azure-Samples) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, macOS, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features.

## Versions
Current version - 1.4.0

Minimum recommended version - 1.4.0

From version 1.3.0 support for handling Conditional Access claims challenge was added. You can read about CA [here](https://go.microsoft.com/fwlink/?linkid=855860) and refer this [sample](https://github.com/AzureAD/azure-activedirectory-library-for-java/tree/dev/src/samples/web-app-samples-for-adal4j) to handle it.

You can find the changes for each version in the [change log](https://github.com/AzureAD/azure-activedirectory-library-for-java/blob/master/changelog.txt).

## Logging

ADAL for Java uses the Simple Logging Facade for Java (SLF4J) as a simple facade or abstraction for various logging frameworks.

#### Personal Identifiable Information (PII) & Organizational Identifiable Information (OII)

By default, ADAL logging does not capture or log any PII or OII. The library allows app developers to turn this on by configuring the logPii property on the AuthenticationContext. By turning on PII or OII, the app takes responsibility for safely handling highly-sensitive data and complying with any regulatory requirements.

```java
//PII or OII logging disabled. Default Logger does not capture any PII or OII
AuthenticationContext context = new AuthenticationContext(...);

//PII or OII logging enabled
context.setLogPii(true);
```

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before.

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## Contributing

All code is licensed under the MIT License and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now.

## We Value and Adhere to the Microsoft Open Source Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
