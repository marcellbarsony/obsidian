# Enums

`enum` is a type that allows to enumerate a list of variants

```rs
enum IpAddrKind {
    V4(u8, u8, u8, u8),
    V6(String),
}

let localhost_v4 = IpAddrKind::V4(127, 0, 0, 1);
let localhost_v6 = IpAddrKind::V6(String::from("::1"));
```

## Methods

```rs
impl IpAddrKind {
    fn get_localhost() {
        println!("{}", IpAddrKind::V6);
    }
}
```

## Match expression

## If-let syntax
