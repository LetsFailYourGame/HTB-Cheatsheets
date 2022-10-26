## Intro to XXE
* `XML External Entity (XXE) Injection`
* Occurs when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions

## XML
* `Extensible Markup Language (XML)`
* Each element is essentially denoted by a `tag`, and the first element is called the `root element`, while other elements are `child elements`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```

![](./Screenshots/Screenshot_2022-10-22_224226.png)

* Some characters are used as part of an XML document structure, like `<`, `>`, `&`, or `"`
* If we need to use them in an XML document, we should replace them with their corresponding entity references (e.g. `&lt;`, `&gt;`, `&amp;`, `&quot;`)

## XML DTD
* `XML Document Type Definition (DTD)`
* Allows the validation of an XML document against a pre-defined document structure
	* Structure can be defined in the document itself or in an external file

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

* Root `email` element with the `ELEMENT` type declaration
* Raw data (as denoted by `PCDATA`)
* Can be declared right after the `XML Declaration` in the first line or can be stored in an external file (e.g. `email.dtd`)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

* Also, possible to reference a DTD through a URL

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

## XML Entities
* We may also define custom entities (i.e. XML variables) in XML DTDs, to allow refactoring of variables and reduce repetitive data
	* Use of the `ENTITY` keyword

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

 * Once defined, entity can be referenced in an XML document between an ampersand `&` and a semi-colon `;` (e.g. `&company;`)
 * Whenever an entity is referenced, it will be replaced with its value by the XML parser
 * We can `reference External XML Entities` with the `SYSTEM` keyword, which is followed by the external entity's path

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

**Note:** We may also use the `PUBLIC` keyword instead of `SYSTEM` for loading external resources, which is used with publicly declared entities and standards, such as a language code (`lang="en"`)

This works similarly to internal XML entities defined within documents. When we reference an external entity (e.g. `&signature;`), the parser will replace the entity with its value stored in the external file (e.g. `signature.txt`). `When the XML file is parsed on the server-side, in cases like SOAP (XML) APIs or web forms, then an entity can reference a file stored on the back-end server, which may eventually be disclosed to us when we reference the entity`