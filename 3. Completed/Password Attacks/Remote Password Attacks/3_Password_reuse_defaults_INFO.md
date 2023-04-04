* Default credentials may be forgotten to be changed after configuration, especially when it comes to internal applications where the administrators assume that no one else will find them and do not even try to use them
* Easy-to-remember passwords that can be typed quickly instead of typing 15-character long passwords are often used repeatedly because [Single-Sign-On](https://en.wikipedia.org/wiki/Single_sign-on) (`SSO`) is not always immediately available during initial installation, and configuration in internal networks requires significant changes
* Often one network device, such as a router, printer, or a firewall, is overlooked, and the `default credentials` are used, or the same `password is reused`

## Credential Stuffing
* [DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) database of known default credentials
* Can also be found in the product documentation
* Some devices/applications require the user to set up a password at install, but others use a default, weak password
* Attacking those services with the default or obtained credentials is called [Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
* We can select the passwords and mutate them by our `rules` to increase the probability of hits
* `OSINT` plays another significant role

#### Credential Stuffing - Hydra Syntax

```sh
hydra -C <user_pass.list> <protocol>://<IP>
```