# Filter files
These files determine patterns to look for, some compatibility with the Fail2Ban format exists however you can do additional pattern matches as well.

## ipregex - Identify a maybe line

The ipregex lines identify a line which 'could' have a match. If one of these match then the code moves into the failregex matches, this means
they are used the most but can also be what slows down processing of 100,000's lines so make them quick to process and dont have too many.

## failregex - What we look for

These lines determine the patterns which could be considered bad and what the matching IP is, each time one of these is matched the hit counter 
is increased by one so if 5 failregex all match one line the hit counter would be increased by 5. 
The only required bit here is that a IP must be returned, this can be matched for IPv4 or IPv6 with *<HOST6>* (Fail2Ban's <HOST> will also work for 
IPv4)

### Matching in sequence
You can also seperate these into sequenced patterns where one must happen before the next one matches which allows for matching on:
1. User logs in
2. User goes to /really.bad.thing
3. User then hits execute

If the user does not do 1 then 2 then 3 then we dont need to monitor it.  **NOTE** If they do 1, 5, 2, 1, 3 then it would still match

Normally all failregex will be treated as one level (eg. any match will be considered a hit) to use sequences add a suffix, eg.
failregex_test1 = login
failregex_test2 = goto /really.bad.thing
failregex_test2 = OR goto /other.really.bad.thing
failregex_test3 = execute


## Includes

Including files relative to the folder.d directory can be done with the command:
```
include FILENAME
```

eg.
```
include common.conf
```
will also include the common.conf file from the filter.d directory
