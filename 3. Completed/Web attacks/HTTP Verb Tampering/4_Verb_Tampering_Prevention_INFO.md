## Insecure Configuration
* Can occur in most modern web servers, including `Apache`, `Tomcat`, and `ASP.NET`
* When we limit a page's authorization to a particular set of HTTP verbs/methods, which leaves the other remaining methods unprotected
* Example of a vulnerable configuration for an Apache

```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

* As the `<Limit GET>` keyword is being used, the `Require valid-user` setting will only apply to `GET` requests, leaving the page accessible through `POST` requests
* Same vulnerability for a `Tomcat` web server

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

* An example for an `ASP.NET`

```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

* Use safe keywords, like `LimitExcept` in Apache, `http-method-omission` in Tomcat, and `add`/`remove` in ASP.NET, which cover all verbs except the specified ones
* To avoid similar attacks, we should generally `consider disabling/denying all HEAD requests` unless specifically required by the web application

## Insecure Coding
* Much harder to fix
* Let's consider the following `PHP` code

```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

* The `preg_match` function properly looks for unwanted special characters
* Does not allow the input to go into the command if any special characters are found
* The fatal error made in this case is not due to Command Injections but due to the `inconsistent use of HTTP methods`
* `preg_match` filter only checks for special characters in `POST` parameters with `$_POST['filename']`
*  `we must be consistent with our use of HTTP methods` and ensure that the same method is always used for any specific functionality across the web application