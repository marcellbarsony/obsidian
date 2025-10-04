# Function constructors

Constructors are creating objects (new struct instances)
with the desired initial state

```rs
let user1 = create_user(
    email: String::from("mail@domain.com"),
    username: String::from("Testuser01")
)

fn create_user(email: String, username: String) -> User {
    User {
        email: email,
        username,         // Field init shorthand syntax
        active: true,     // Default value
        sign_in_count: 1, // Default value
    }
}
```
