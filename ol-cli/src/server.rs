//! server

#![deny(warnings)]
use std::sync::Arc;

use handlebars::Handlebars;
use serde::Serialize;
use serde_json::json;
use warp::Filter;

struct WithTemplate<T: Serialize> {
    name: &'static str,
    value: T,
}

fn render<T>(template: WithTemplate<T>, hbs: Arc<Handlebars>) -> impl warp::Reply
where
    T: Serialize,
{
    let render = hbs
        .render(template.name, &template.value)
        .unwrap_or_else(|err| err.to_string());
    warp::reply::html(render)
}

/// main server
#[tokio::main]
pub async fn main() {
    let template = "<!DOCTYPE html>
                    <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/uikit@3.6.18/dist/css/uikit.min.css\" />
                    <script src='https://cdn.jsdelivr.net/npm/uikit@3.6.18/dist/js/uikit.min.js'></script>
                    <script src='https://cdn.jsdelivr.net/npm/uikit@3.6.18/dist/js/uikit-icons.min.js'></script>
                    <html>
                      <head>
                        <title>Warp Handlebars template example</title>
                      </head>
                      <body>
                        <h1>Hello {{user}}!</h1>
                      </body>
                    </html>";

    let mut hb = Handlebars::new();
    // register the template
    hb.register_template_string("template.html", template)
        .unwrap();

    // Turn Handlebars instance into a Filter so we can combine it
    // easily with others...
    let hb = Arc::new(hb);

    // Create a reusable closure to render template
    let handlebars = move |with_template| render(with_template, hb.clone());

    //GET /
    let route = warp::get()
        .and(warp::path::end())
        .map(|| WithTemplate {
            name: "template.html",
            value: json!({"user" : "helllo"}),
        })
        .map(handlebars);

    warp::serve(route).run(([127, 0, 0, 1], 3030)).await;
}