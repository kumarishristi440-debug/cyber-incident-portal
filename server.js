const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const app = express();

const PORT = 3000;
const JWT_SECRET = "cyberportal_secret_key";

// ==============================
// MIDDLEWARE
// ==============================

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend files
app.use(express.static("public"));

// Serve uploaded evidence files
app.use("/uploads", express.static("uploads"));


// ==============================
// MONGODB CONNECTION
// ==============================

mongoose
    .connect("mongodb://127.0.0.1:27017/cyberIncidentPortal")
    .then(() => {
        console.log("MongoDB Connected");
    })
    .catch((error) => {
        console.log("MongoDB Connection Error:", error);
    });


// ==============================
// USER SCHEMA
// ==============================

const userSchema = new mongoose.Schema({

    name: {
        type: String,
        required: true
    },

    email: {
        type: String,
        required: true,
        unique: true
    },

    password: {
        type: String,
        required: true
    },

    role: {
        type: String,
        default: "user"
    }

});

const User = mongoose.model("User", userSchema);


// ==============================
// INCIDENT SCHEMA
// ==============================

const incidentSchema = new mongoose.Schema({

    incidentId: {
        type: String,
        unique: true
    },

    reporter: {
        type: String,
        required: true
    },

    email: String,

    incidentType: {
        type: String,
        required: true
    },

    title: {
        type: String,
        required: true
    },

    description: {
        type: String,
        required: true
    },

    affectedSystem: {
        type: String,
        required: true
    },

    severity: {
        type: String,
        required: true
    },

    riskScore: {
        type: Number,
        default: 0
    },

    status: {
        type: String,
        default: "Reported"
    },

    evidence: {
        type: String,
        default: "No evidence"
    },

    createdAt: {
        type: Date,
        default: Date.now
    },

    updates: [
        {
            message: String,

            date: {
                type: Date,
                default: Date.now
            }
        }
    ]

});

const Incident =
    mongoose.model("Incident", incidentSchema);


// ==============================
// FILE UPLOAD CONFIGURATION
// ==============================

const storage = multer.diskStorage({

    destination: function (req, file, cb) {

        cb(null, "uploads/");

    },

    filename: function (req, file, cb) {

        const uniqueName =
            Date.now() + "-" + file.originalname;

        cb(null, uniqueName);

    }

});

const upload = multer({
    storage: storage
});


// ==============================
// USER REGISTRATION
// ==============================

app.post("/api/register", async (req, res) => {

    try {

        const {
            name,
            email,
            password
        } = req.body;


        // Check whether user already exists

        const existingUser =
            await User.findOne({ email });


        if (existingUser) {

            return res.status(400).json({

                message:
                    "User already exists"

            });

        }


        // Encrypt password

        const hashedPassword =
            await bcrypt.hash(password, 10);


        // Create user

        const user = new User({

            name: name,

            email: email,

            password: hashedPassword,

            role: "user"

        });


        await user.save();


        res.json({

            message:
                "Registration successful"

        });


    } catch (error) {

        console.log(error);

        res.status(500).json({

            message:
                "Registration failed"

        });

    }

});


// ==============================
// USER LOGIN
// ==============================

app.post("/api/login", async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;


        // Find user

        const user =
            await User.findOne({ email });


        if (!user) {

            return res.status(401).json({

                message:
                    "Invalid email or password"

            });

        }


        // Compare password

        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password
            );


        if (!passwordMatch) {

            return res.status(401).json({

                message:
                    "Invalid email or password"

            });

        }


        // Generate JWT token

        const token = jwt.sign(

            {
                id: user._id,

                email: user.email,

                role: user.role
            },

            JWT_SECRET,

            {
                expiresIn: "2h"
            }

        );


        res.json({

            message:
                "Login successful",

            token: token,

            user: {

                name: user.name,

                email: user.email,

                role: user.role

            }

        });


    } catch (error) {

        console.log(error);

        res.status(500).json({

            message:
                "Login failed"

        });

    }

});


// ==============================
// AUTHENTICATION MIDDLEWARE
// ==============================

function authenticate(req, res, next) {

    // Get token from Authorization header

    const authHeader =
        req.headers.authorization;


    if (!authHeader) {

        return res.status(401).json({

            message:
                "Access denied. Please login."

        });

    }


    const token =
        authHeader.split(" ")[1];


    if (!token) {

        return res.status(401).json({

            message:
                "Token missing"

        });

    }


    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );


        req.user = decoded;


        next();


    } catch (error) {

        return res.status(401).json({

            message:
                "Invalid or expired token"

        });

    }

}


// ==============================
// RISK SCORE CALCULATOR
// ==============================

function calculateRisk(severity) {

    switch (severity) {

        case "Critical":
            return 90;

        case "High":
            return 70;

        case "Medium":
            return 45;

        case "Low":
            return 20;

        default:
            return 0;

    }

}


// ==============================
// REPORT INCIDENT
// ==============================

app.post(
    "/api/incidents",
    authenticate,
    upload.single("evidence"),
    async (req, res) => {

        try {

            const {

                incidentType,

                title,

                description,

                affectedSystem,

                severity

            } = req.body;


            // Generate unique incident ID

            const incidentId =
                "INC-" +
                Date.now()
                    .toString()
                    .slice(-6);


            // Calculate risk

            const riskScore =
                calculateRisk(severity);


            // Create incident

            const incident =
                new Incident({

                    incidentId:

                        incidentId,

                    reporter:

                        req.user.email,

                    email:

                        req.user.email,

                    incidentType:

                        incidentType,

                    title:

                        title,

                    description:

                        description,

                    affectedSystem:

                        affectedSystem,

                    severity:

                        severity,

                    riskScore:

                        riskScore,

                    status:

                        "Reported",

                    evidence:

                        req.file
                            ? req.file.filename
                            : "No evidence",

                    updates: [

                        {

                            message:
                                "Incident reported",

                            date:
                                new Date()

                        }

                    ]

                });


            // Save incident to MongoDB

            await incident.save();


            res.json({

                message:
                    "Incident reported successfully",

                incidentId:
                    incidentId,

                riskScore:
                    riskScore

            });


        } catch (error) {

            console.log(error);

            res.status(500).json({

                message:
                    "Could not submit incident"

            });

        }

    }
);


// ==============================
// GET USER'S INCIDENTS
// ==============================

app.get(
    "/api/my-incidents",
    authenticate,
    async (req, res) => {

        try {

            const incidents =
                await Incident.find({

                    reporter:
                        req.user.email

                })
                .sort({
                    createdAt: -1
                });


            res.json(incidents);


        } catch (error) {

            console.log(error);

            res.status(500).json({

                message:
                    "Could not fetch incidents"

            });

        }

    }
);


// ==============================
// GET ALL INCIDENTS
// ADMIN ONLY
// ==============================

app.get(
    "/api/incidents",
    authenticate,
    async (req, res) => {

        try {

            // Check admin role

            if (req.user.role !== "admin") {

                return res.status(403).json({

                    message:
                        "Admin access required"

                });

            }


            const incidents =
                await Incident.find()
                    .sort({
                        createdAt: -1
                    });


            res.json(incidents);


        } catch (error) {

            console.log(error);

            res.status(500).json({

                message:
                    "Could not fetch incidents"

            });

        }

    }
);


// ==============================
// UPDATE INCIDENT STATUS
// ADMIN ONLY
// ==============================

app.put(
    "/api/incidents/:id",
    authenticate,
    async (req, res) => {

        try {

            // Check admin

            if (req.user.role !== "admin") {

                return res.status(403).json({

                    message:
                        "Admin access required"

                });

            }


            const {
                status
            } = req.body;


            // Find incident

            const incident =
                await Incident.findById(
                    req.params.id
                );


            if (!incident) {

                return res.status(404).json({

                    message:
                        "Incident not found"

                });

            }


            // Update status

            incident.status =
                status;


            // Add timeline update

            incident.updates.push({

                message:
                    "Status changed to " +
                    status,

                date:
                    new Date()

            });


            await incident.save();


            res.json({

                message:
                    "Incident status updated successfully"

            });


        } catch (error) {

            console.log(error);

            res.status(500).json({

                message:
                    "Could not update incident"

            });

        }

    }
);


// ==============================
// CREATE ADMIN ACCOUNT
// ==============================

app.get(
    "/create-admin",
    async (req, res) => {

        try {

            const adminEmail =
                "admin@cyberportal.com";


            // Check whether admin exists

            const existingAdmin =
                await User.findOne({

                    email:
                        adminEmail

                });


            if (existingAdmin) {

                return res.send(

                    "Admin already exists."

                );

            }


            // Encrypt admin password

            const hashedPassword =
                await bcrypt.hash(
                    "admin123",
                    10
                );


            // Create admin

            const admin =
                new User({

                    name:
                        "Cyber Security Admin",

                    email:
                        adminEmail,

                    password:
                        hashedPassword,

                    role:
                        "admin"

                });


            await admin.save();


            res.send(

                "Admin created successfully.<br><br>" +

                "Email: admin@cyberportal.com<br>" +

                "Password: admin123"

            );


        } catch (error) {

            console.log(error);

            res.status(500).send(

                "Could not create admin"

            );

        }

    }
);


// ==============================
// HOME ROUTE
// ==============================

app.get("/", (req, res) => {

    res.sendFile(
        __dirname +
        "/public/index.html"
    );

});


// ==============================
// START SERVER
// ==============================

app.listen(
    PORT,
    () => {

        console.log(
            "================================"
        );

        console.log(
            "CyberShield Portal Started"
        );

        console.log(
            `Open: http://localhost:${PORT}`
        );

        console.log(
            "================================"
        );

    }
);