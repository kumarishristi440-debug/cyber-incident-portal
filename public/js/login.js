// ==============================
// LOGIN FORM
// ==============================

document
    .getElementById("loginForm")
    .addEventListener("submit", async function(event) {

        event.preventDefault();


        // Get input values

        const email =
            document.getElementById("email").value;

        const password =
            document.getElementById("password").value;


        try {


            // Send login request to server

            const response =
                await fetch("/api/login", {

                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body: JSON.stringify({

                        email: email,

                        password: password

                    })

                });



            const data =
                await response.json();



            // If login successful

            if (response.ok) {


                // Store JWT token

                localStorage.setItem(
                    "token",
                    data.token
                );


                // Store user information

                localStorage.setItem(
                    "user",
                    JSON.stringify(data.user)
                );


                alert(
                    "Login successful!"
                );


                // Check user role

                if (data.user.role === "admin") {

                    window.location.href =
                        "admin.html";

                }

                else {

                    window.location.href =
                        "dashboard.html";

                }


            }

            else {


                document.getElementById(
                    "message"
                ).innerText =
                    data.message;


            }


        }

        catch (error) {


            console.log(error);


            document.getElementById(
                "message"
            ).innerText =
                "Unable to connect to server.";


        }

    });



// ==============================
// REGISTER USER
// ==============================

async function registerUser() {


    // Ask user for details

    const name =
        prompt("Enter your full name:");


    if (!name) {

        return;

    }


    const email =
        prompt("Enter your email:");


    if (!email) {

        return;

    }


    const password =
        prompt("Create a password:");


    if (!password) {

        return;

    }



    try {


        // Send registration request

        const response =
            await fetch("/api/register", {

                method: "POST",

                headers: {

                    "Content-Type":
                        "application/json"

                },

                body: JSON.stringify({

                    name: name,

                    email: email,

                    password: password

                })

            });



        const data =
            await response.json();



        alert(
            data.message
        );


    }

    catch (error) {


        console.log(error);


        alert(
            "Unable to connect to server."
        );


    }

}