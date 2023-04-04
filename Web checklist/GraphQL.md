* Check if Introspection is enabled
	* Should be disabled (*INFO*)
	* Check Querys and Mutations
	* Check If Mutations can called 
	* Check for [Batching](https://lab.wallarm.com/graphql-batching-attack/) Attacks

```url
fragment+FullType+on+__Type+%7B++kind++name++description++fields(includeDeprecated%3a+true)+%7B++++name++++description++++args+%7B++++++...InputValue++++%7D++++type+%7B++++++...TypeRef++++%7D++++isDeprecated++++deprecationReason++%7D++inputFields+%7B++++...InputValue++%7D++interfaces+%7B++++...TypeRef++%7D++enumValues(includeDeprecated%3a+true)+%7B++++name++++description++++isDeprecated++++deprecationReason++%7D++possibleTypes+%7B++++...TypeRef++%7D%7Dfragment+InputValue+on+__InputValue+%7B++name++description++type+%7B++++...TypeRef++%7D++defaultValue%7Dfragment+TypeRef+on+__Type+%7B++kind++name++ofType+%7B++++kind++++name++++ofType+%7B++++++kind++++++name++++++ofType+%7B++++++++kind++++++++name++++++++ofType+%7B++++++++++kind++++++++++name++++++++++ofType+%7B++++++++++++kind++++++++++++name++++++++++++ofType+%7B++++++++++++++kind++++++++++++++name++++++++++++++ofType+%7B++++++++++++++++kind++++++++++++++++name++++++++++++++%7D++++++++++++%7D++++++++++%7D++++++++%7D++++++%7D++++%7D++%7D%7Dquery+IntrospectionQuery+%7B++__schema+%7B++++queryType+%7B++++++name++++%7D++++mutationType+%7B++++++name++++%7D++++types+%7B++++++...FullType++++%7D++++directives+%7B++++++name++++++description++++++locations++++++args+%7B++++++++...InputValue++++++%7D++++%7D++%7D%7D
```

