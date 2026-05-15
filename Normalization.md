Milestone 2 Normalization Report

For Milestone 2, we went through the Version 1.2 schema for our SecureVault project to make sure everything lines up with the three main database normal forms. The goal was just to clean things up, stop data from repeating, and make the whole structure run smoother.

First Normal Form (1NF)
For 1NF, the main rule is that every piece of data has to be atomic (so no grouped or repeating values in a single cell) and every row needs a unique ID. Our SecureVault schema already does this perfectly. Every column like username, encrypted password, or site name just holds one single piece of info. Plus, every single table has its own proper Primary Key like user id, vault id, or bank id, so there is no confusion between records.

Second Normal Form (2NF)
Once 1NF is sorted, 2NF basically says all the non key columns have to depend on the whole Primary Key to stop partial dependencies. Since we used simple, single column auto incrementing IDs for all our primary keys, we don't even have composite keys to begin with. Because of that, partial dependency just is not possible in our setup. Everything in a table depends directly on that table's specific ID, so we hit 2NF compliance right off the bat without having to change anything.

Third Normal Form (3NF)
The last step was making sure we meet 3NF by getting rid of transitive dependencies, which happens when a non key column depends on another non key column. We actually caught this stuff early on when we were first designing the database. For example, things like clipboard timeouts or re authentication rules depend on the type of credential, not the specific password entry itself. So, we made a separate credential types table and just linked it to the main vault table using a foreign key. This way, if we update a security rule, it applies everywhere without us having to type it in multiple times. That pretty much seals our 3NF compliance.

Redundancy and Relationship Refinement
Besides the normal forms, we also double checked the schema to make sure we aren't bloating the database with duplicate info. For example, our audit log and password history tables only store reference IDs instead of writing out the actual usernames or URLs over and over. Also, we set up a strict one to one relationship between the normal vault entries and the banking credentials. This keeps the main vault table clean for regular logins, while locking down the really sensitive bank details in their own separate table. Our updated ERD shows all these one to one and one to many relationships exactly as they are.