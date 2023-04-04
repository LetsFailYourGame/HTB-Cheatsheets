## Password Policy
* A [password policy](https://en.wikipedia.org/wiki/Password_policy) is a set of rules designed to enhance computer security by encouraging users to employ strong passwords and use them adequately based on the company's definition
* The scope of a password policy is not limited to the password minimum requirements but the whole life cycle of a password (such as manipulation, storage, and transmission)

## Password Policy Standards
* Because of compliance and best practices, many companies use [IT security standards](https://en.wikipedia.org/wiki/IT_security_standards)
* Although complying with a standard does not mean that we are 100% secure, it is a common practice within the industry that defines a baseline of security controls for organizations
* That should not be the only way to measure the effectiveness of the organizational security controls
* Some security standards include a section for password policies or password guidelines
	1.  [NIST SP800-63B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf)
	2.  [CIS Password Policy Guide](https://www.cisecurity.org/insights/white-papers/cis-password-policy-guide)
	3.  [PCI DSS](https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss)
* We can use those standards to understand different perspectives of password policies
* After that, we can use this information to create our password policy
* Let us take a use case where different standards use a different approach, `password expiration`
* `Change your password periodically (e.g., 90 days) to be more secure` may be a phrase we heard a couple of times, but the truth is that not every company is using this policy
* Some companies only require their users to change their passwords when there is evidence of compromise
* If we look at some of the above standards, some require users to change the password periodically, and others do not

## Password Policy Recommendations
* Let us create a sample password policy to illustrate some important things to keep in mind while creating a password policy
	- Minimum of 8 characters
	- Include uppercase and lowercase letters
	- Include at least one number
	- Include at least one special character
	- It should not be the username
	- It should be changed every 60 days
- Blocklist
	- Company's name
	- Common words associated with the company
	- Names of months
	- Names of seasons
	- Variations on the word welcome and password
	- Common and guessable words such as password, 123456, and abcde

## Enforcing Password Policy
* A password policy is a guide that defines how we should create, manipulate and store passwords in the organization
* To apply this guide, we need to enforce it, using the technology at our disposal or acquiring what needs to make this work
* If we use Active Directory for authentication, we need to configure an [Active Directory Password Policy GPO](https://activedirectorypro.com/how-to-configure-a-domain-password-policy/), to enforce our users to comply with our password policy

## Creating a Good password
* Use [PasswordMonster](https://www.passwordmonster.com/), a website that helps us test how strong our passwords are, and [PasswordsGenerator](https://passwordsgenerator.net/), another website to generate secure passwords