# Stupid 2FA

A simple way to authenticate client app without cloud


## use

This project use the env variable `STUPID_2FA_PRIVATE_KEY` as the private key

An simple example of it working

```rust
fn main() {
    let lock_code = generate_lock_code();
    println!("Lock Code: {}", lock_code);

    let subscription_days = 30;
    let unlock_code = generate_unlock_code(&lock_code, subscription_days);
    println!("Unlock Code: {}", unlock_code);

    let is_valid = validate_unlock_code(&lock_code, &unlock_code, subscription_days);
    println!("Is Unlock Code Valid? {}", is_valid);
}
```


## Functionalities

- HMAC-based auth


## Reference
some articles on the topic of authentication

 - [Message authentication code (MAC)](https://www.wikiwand.com/en/Message_authentication_code)
 - [HMAC](https://www.wikiwand.com/en/HMAC)
 - [HMAC-based one-time password](https://www.wikiwand.com/en/HMAC-based_one-time_password)


## License

[MIT](https://choosealicense.com/licenses/mit/)


## contributing

Contributions are always welcome!
any suggestions, open a pull request or a issue.

*code of conduct*: format your code, thx.


