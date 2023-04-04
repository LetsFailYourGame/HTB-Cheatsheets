## Nginx - Enabling PUT
When allowing `HTTP` uploads, it is critical to be 100% positive that users cannot upload web shells and execute them. `Apache` makes it easy to shoot ourselves in the foot with this, as the `PHP` module loves to execute anything ending in `PHP`. Configuring `Nginx` to use PHP is nowhere near as simple.

#### Create a Directory to Handle Uploaded Files
```sh
$ sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```

#### Change the Owner to www-data
```sh
$ sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

#### Create Nginx Configuration File
* Create  `/etc/nginx/sites-available/upload.conf`

```sh
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

#### Symlink our Site to the sites-enabled Directory
```sh
$ sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

#### Start Nginx
```sh
$ sudo systemctl restart nginx.service
```

#### Remove NginxDefault Configuration
```sh
$ sudo rm /etc/nginx/sites-enabled/default
```

#### Upload File Using cURL
```sh
$ curl -T /etc/passwd 
http://localhost:9001/SecretUploadDirectory/users.txt
```

```sh
# tail -1 /var/www/upload/SecretUploadDirectory/users.txt 

user65:x:1000:1000:,,,:/home/user65:/bin/bash
```

* Disable directory listing