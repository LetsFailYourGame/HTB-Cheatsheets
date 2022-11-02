* `Relational Databases`
	* Utilize SQL
*  `Non-Relational`
	* Utilize a variety of methods for communications

## Relational Databases
* Most common type of database
* Uses a `schema`, `template` to dictate the data structure stored in the database
* Tables in a relational database are associated with keys
	* Provide a quick database summary or access to the specific row or column when specific data needs to be reviewed
	* Tables also called entities are all related to each other
* When processing an integrated database
	* Concept is required to link one table to another using its key
	* `relational database management system` (`RDBMS`)

![[../../Screenshots/web_apps_relational_db.jpg]]

## Non-relational Databases
* Also called `NoSQL` 
* Most popular database `MongoDB`
* Does not use tables, rows, and columns or prime keys, relationships, or schemas
* Stores data using various storage models, depending on which type of data stored
	-   Key-Value
	-   Document-Based
	-   Wide-Column
	-   Graph
* Very scalable and flexible
* Example for a key-value model

```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

**Note** Non-relational Databases have a different method for injection, known as NoSQL injections. SQL injections are completely different from NoSQL injections.