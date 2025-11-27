---
id: Usage
aliases: []
tags:
  - Networking/Services/MongoDB/Usage
---

# Usage

___

<!-- Install {{{-->
## Install

[MongoDB - Install](https://www.mongodb.com/docs/mongodb-shell/install/?debian-version=debian12&linux-distribution=debian&operating-system=linux)

<!-- Latest {{{-->
### Latest

<!-- Warning {{{-->
> [!warning]
>
> The MongoDB server running on Mongod is only compatible
> with Mongo Shell version <= `2.3.2` (*[[#Legacy]]*)
>
> > [!example]- MongoServerSelectionError
> >
> > ```sh
> > MongoServerSelectionError: Server at 10.129.228.30:27017 reports maximum wire version 6, but this version of the Node.js Driver requires at least 8 (MongoDB 4.2)
> > ```
<!-- }}} -->

1. Import the public key used for the package management system

```sh
wget -qO- https://www.mongodb.org/static/pgp/server-8.0.asc | sudo tee /etc/apt/trusted.gpg.d/server-8.0.asc
```

2. Create a list file for MongoDB

```sh
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/debian bullseye/mongodb-org/8.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list
```

3. Reload the local package database

```sh
sudo apt-get update
```

4. Install `mongosh`

```sh
sudo apt-get install -y mongodb-mongosh
```

<!-- }}} -->

<!-- Legacy {{{-->
### Legacy

Install a legacy version of `mongosh` as the [[#Latest]] may cause errors


1. Download the tar archive

```sh
wget https://downloads.mongodb.com/compass/mongosh-2.3.2-linux-x64.tgz
```

2. Extract the tarball

```sh
tar -xzf mongosh-2.3.2-linux-x64.tgz
```

3. Install the binary

```sh
sudo install -m755 mongosh-2.3.2-linux-x64/bin/mongosh /usr/local/bin/mongosh
```

<!-- }}} -->

<!-- Mongo Tools {{{-->
### Mongo Tools

[Kali - Mongo-Tools](https://www.kali.org/tools/mongo-tools/)

```sh
sudo apt install mongo-tools
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Connect {{{-->
## Connect

[Mongosh](https://www.mongodb.com/docs/mongodb-shell/) —
Connect remotely

```sh
mongosh "mongodb://<target_ip>:<port>"
```

Mongo Shell

```sh
mongo <target_ip>:<port>
```

___
<!-- }}} -->

<!-- Database {{{-->
## Databases

Databate operations — Enumerate databases to identify high-value targets

<!-- Discover {{{-->
### Discover

List all databases

```sql
show dbs
```

```sql
db.adminCommand('listDatabases')
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> test> show dbs
> ```
> ```sh
> admin                  32.00 KiB
> config                 72.00 KiB
> local                  72.00 KiB
> sensitive_information  32.00 KiB
> users                  32.00 KiB
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Select {{{-->
### Select

Select a database

```sql
use database_name
```

<!-- Example {{{-->
> [!example]-
>
> ```sql
> test> use sensitive_information
> ```
> ```sql
> switched to db sensitive_information
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Collections {{{-->
## Collections

Extract database collection information

<!-- Discover {{{-->
### Discover

List collection in current database

```sql
show collections
```

```sql
db.getCollectionNames()
```

<!-- }}} -->

<!-- Statistics {{{-->
### Statistics

Show collection statistics

```sql
db.collection_name.stats()
```

```sql
db.collection_name.count()
```

<!-- }}} -->

<!-- Query {{{-->
### Query

Query collection content

```sql
db.flag.find()
```

```sql
db.flag.find().pretty()
```

```sql
db.flag.findOne()
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sensitive_information> db.flag.find()
> ```
> ```sh
> [
>   {
>     _id: ObjectId('630e3dbcb82540ebbd1748c5'),
>     flag: '1b6e6fb359e7c40241b6d431427ba6ea'
>   }
> ]
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
