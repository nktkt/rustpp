use proc_macro::{Delimiter, Group, TokenStream, TokenTree};

#[proc_macro_attribute]
pub fn component(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro_attribute]
pub fn effects(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro_attribute]
pub fn unsafe_boundary(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro_attribute]
pub fn requires(attr: TokenStream, item: TokenStream) -> TokenStream {
    let condition = attr.to_string();
    let message = escaped_message("Rust++ requires failed", &condition);
    let statement = format!("debug_assert!(({condition}), {message});");

    let Ok(statement) = statement.parse::<TokenStream>() else {
        return compile_error("`#[requires]` could not parse its generated assertion");
    };

    rewrite_function_body(item, |body| {
        let mut rewritten = TokenStream::new();
        rewritten.extend(statement);
        rewritten.extend(body);
        rewritten
    })
}

#[proc_macro_attribute]
pub fn ensures(attr: TokenStream, item: TokenStream) -> TokenStream {
    let condition = attr.to_string();
    let message = escaped_message("Rust++ ensures failed", &condition);
    let Ok(prefix) = "let __rustpp_result =".parse::<TokenStream>() else {
        return compile_error("`#[ensures]` could not parse its generated prefix");
    };
    let tail = format!(
        "; let result = &__rustpp_result; debug_assert!(({condition}), {message}); __rustpp_result"
    );
    let Ok(tail) = tail.parse::<TokenStream>() else {
        return compile_error("`#[ensures]` could not parse its generated assertion");
    };

    rewrite_function_body(item, |body| {
        let mut rewritten = TokenStream::new();
        rewritten.extend(prefix);
        rewritten.extend([TokenTree::Group(Group::new(Delimiter::Brace, body))]);
        rewritten.extend(tail);
        rewritten
    })
}

fn rewrite_function_body(
    item: TokenStream,
    rewrite: impl FnOnce(TokenStream) -> TokenStream,
) -> TokenStream {
    let mut rewritten = TokenStream::new();
    let mut rewrite = Some(rewrite);

    for token in item {
        match token {
            TokenTree::Group(group)
                if group.delimiter() == Delimiter::Brace && rewrite.is_some() =>
            {
                let span = group.span();
                let body = rewrite.take().expect("rewrite closure should exist")(group.stream());
                let mut new_group = Group::new(Delimiter::Brace, body);
                new_group.set_span(span);
                rewritten.extend([TokenTree::Group(new_group)]);
            }
            token => rewritten.extend([token]),
        }
    }

    if rewrite.is_some() {
        return compile_error("contract attributes can only be applied to functions with a body");
    }

    rewritten
}

fn escaped_message(prefix: &str, condition: &str) -> String {
    let escaped = condition.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{prefix}: {escaped}\"")
}

fn compile_error(message: &str) -> TokenStream {
    let escaped = message.replace('\\', "\\\\").replace('"', "\\\"");
    format!("compile_error!(\"{escaped}\");")
        .parse()
        .expect("generated compile_error should parse")
}
