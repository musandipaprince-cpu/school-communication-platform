
require("dotenv").config();

const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = 3000;

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
});

// Verify login token
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            message: "Access denied. Please log in."
        });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({
                message: "Invalid or expired token."
            });
        }

        req.user = decoded;
        next();
    });
}

// Check user role permissions
function allowRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                message: "Access denied. You do not have permission."
            });
        }

        next();
    };
}

// Home route
app.get("/", (req, res) => {
    res.send("School Communication Platform is running!");
});

// Hello route
app.get("/hello", (req, res) => {
    res.send("The new route works!");
});

// Test database connection
app.get("/test-db", async (req, res) => {
    try {
        const [rows] = await db.query(
            "SELECT DATABASE() AS database_name"
        );

        res.json({
            message: "Database connection successful!",
            database: rows[0].database_name
        });
    } catch (error) {
        console.error("Database connection error:", error.message);
        res.status(500).json({
            message: "Database connection failed. Check your local settings."
        });
    }
});

// Retrieve users (administrators only)
app.get(
    "/users",
    verifyToken,
    allowRoles("admin"),
    async (req, res) => {
        try {
            const { role } = req.query;

            let sql =
                "SELECT user_id, first_name, surname, email, role FROM users";
            const params = [];

            if (role) {
                sql += " WHERE role = ?";
                params.push(role);
            }

            const [rows] = await db.query(sql, params);

            res.json({
                total: rows.length,
                users: rows
            });
        } catch (error) {
            console.error("Users route error:", error.message);
            res.status(500).json({
                message: "Could not retrieve users."
            });
        }
    }
);

// Login
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required."
            });
        }

        const [users] = await db.execute(
            `SELECT user_id, first_name, surname, email, role, password
             FROM users WHERE email = ?`,
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        const user = users[0];

        const passwordMatches = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatches) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        const token = jwt.sign(
            {
                user_id: user.user_id,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({
            message: "Login successful!",
            token: token,
            user: {
                user_id: user.user_id,
                first_name: user.first_name,
                surname: user.surname,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Login error:", error.message);
        res.status(500).json({
            message: "An error occurred while logging in."
        });
    }
});

// Create an announcement (administrators and teachers)
app.post(
    "/announcements",
    verifyToken,
    allowRoles("admin", "teacher"),
    async (req, res) => {
        try {
            const { title, message } = req.body;

            if (!title || !message) {
                return res.status(400).json({
                    message: "Title and message are required."
                });
            }

            const [result] = await db.execute(
                `INSERT INTO announcements (title, message, created_by)
                 VALUES (?, ?, ?)`,
                [title, message, req.user.user_id]
            );

            res.status(201).json({
                message: "Announcement created successfully!",
                announcement_id: result.insertId
            });
        } catch (error) {
            console.error("Announcement error:", error.message);
            res.status(500).json({
                message: "Could not create announcement."
            });
        }
    }
);


 // Create a classroom (administrators and teachers)
app.post(
    "/classrooms",
    verifyToken,
    allowRoles("admin", "teacher"),
    async (req, res) => {
        try {
            const { classroom_name, description } = req.body;

            if (!classroom_name || !classroom_name.trim()) {
                return res.status(400).json({
                    message: "Classroom name is required."
                });
            }

            const [result] = await db.execute(
                `INSERT INTO classrooms
                 (classroom_name, description, teacher_id)
                 VALUES (?, ?, ?)`,
                [
                    classroom_name.trim(),
                    description || null,
                    req.user.user_id
                ]
            );

            res.status(201).json({
                message: "Classroom created successfully!",
                classroom_id: result.insertId
            });
        } catch (error) {
            console.error("Classroom error:", error.message);
            res.status(500).json({
                message: "Could not create classroom."
            });
        }
    }
);


/* Create an assignment or share a learning resource */
app.post(
    "/resources",
    verifyToken,
    allowRoles("admin", "teacher"),
    async (req, res) => {
        try {
            const {
                classroom_id,
                title,
                description,
                resource_url,
                due_date
            } = req.body;

            if (!classroom_id || !title || !title.trim()) {
                return res.status(400).json({
                    message: "Classroom ID and title are required."
                });
            }

            const [result] = await db.execute(
                `INSERT INTO assignment_resources
                (classroom_id, teacher_id, title, description,
                 resource_url, due_date)
                VALUES (?, ?, ?, ?, ?, ?)`,
                [
                    classroom_id,
                    req.user.user_id,
                    title.trim(),
                    description || null,
                    resource_url || null,
                    due_date || null
                ]
            );

            res.status(201).json({
                message: "Assignment resource shared successfully!",
                resource_id: result.insertId
            });
        } catch (error) {
            console.error("Resource error:", error.message);
            res.status(500).json({
                message: "Could not share the resource. Check the classroom ID."
            });
        }
    }
);

/* View assignment resources */
app.get(
    "/resources",
    verifyToken,
    async (req, res) => {
        try {
            const [resources] = await db.execute(
                `SELECT resource_id, classroom_id, teacher_id,
                        title, description, resource_url,
                        due_date, created_at
                 FROM assignment_resources
                 ORDER BY created_at DESC`
            );

            res.json(resources);
        } catch (error) {
            console.error("Resource retrieval error:", error.message);
            res.status(500).json({
                message: "Could not retrieve resources."
            });
        }
    }
);


// Retrieve announcements (all logged-in users)
app.get("/announcements", verifyToken, async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT a.announcement_id, a.title, a.message,
                   a.created_at, u.first_name, u.surname, u.role
            FROM announcements a
            JOIN users u ON a.created_by = u.user_id
            ORDER BY a.created_at DESC
        `);

        res.json({
            total: rows.length,
            announcements: rows
        });
    } catch (error) {
        console.error("Announcements error:", error.message);
        res.status(500).json({
            message: "Could not retrieve announcements."
        });
    }
});

// Create a notification (administrators and teachers)
app.post(
    "/notifications",
    verifyToken,
    allowRoles("admin", "teacher"),
    async (req, res) => {
        try {
            const { user_id, message } = req.body;

            if (!user_id || !message) {
                return res.status(400).json({
                    message: "user_id and message are required."
                });
            }

            const [result] = await db.execute(
                
`INSERT INTO notifications (user_id, message, delivery_status)
 VALUES (?, ?, 'sent')`,
[user_id, message]

            );

            res.status(201).json({
                message: "Notification created successfully!",
                notification_id: result.insertId
            });
        } catch (error) {
            console.error("Notification error:", error.message);
            res.status(500).json({
                message: "Could not create notification."
            });
        }
    }
);

// Retrieve notifications
app.get("/notifications", verifyToken, async (req, res) => {
    try {
        const { user_id } = req.query;

        let sql = `
            SELECT notification_id, user_id, message, status, created_at
            FROM notifications
        `;

        const params = [];

        if (req.user.role === "student" || req.user.role === "parent") {
            sql += " WHERE user_id = ?";
            params.push(req.user.user_id);
        } else if (user_id) {
            sql += " WHERE user_id = ?";
            params.push(user_id);
        }

        sql += " ORDER BY created_at DESC";

        const [rows] = await db.query(sql, params);

        res.json({
            total: rows.length,
            notifications: rows
        });
    } catch (error) {
        console.error("Notification retrieval error:", error.message);
        res.status(500).json({
            message: "Could not retrieve notifications."
        });
    }
});

// Mark a notification as read
app.patch(
    "/notifications/:id/read",
    verifyToken,
    async (req, res) => {
        try {
            const { id } = req.params;

            let sql = `
                UPDATE notifications
                SET status = 'read'
                WHERE notification_id = ?
            `;

            const params = [id];

            // Students and parents may update only their own notifications
            if (
                req.user.role === "student" ||
                req.user.role === "parent"
            ) {
                sql += " AND user_id = ?";
                params.push(req.user.user_id);
            } else if (
                req.user.role !== "admin" &&
                req.user.role !== "teacher"
            ) {
                return res.status(403).json({
                    message: "Access denied. You do not have permission."
                });
            }

            const [result] = await db.execute(sql, params);

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    message: "Notification not found or access denied."
                });
            }

            res.json({
                message: "Notification marked as read successfully!"
            });
        } catch (error) {
            console.error("Mark as read error:", error.message);
            res.status(500).json({
                message: "Could not update notification."
            });
        }
    }
);


/* Schedule a reminder for a user */
app.post(
    "/reminders",
    verifyToken,
    allowRoles("admin", "teacher"),
    async (req, res) => {
        try {
            const { user_id, message, scheduled_at } = req.body;

            if (!user_id || !message || !scheduled_at) {
                return res.status(400).json({
                    message: "user_id, message and scheduled_at are required."
                });
            }

            const scheduledDate = new Date(scheduled_at);

            if (Number.isNaN(scheduledDate.getTime())) {
                return res.status(400).json({
                    message: "Please provide a valid scheduled date and time."
                });
            }

            if (scheduledDate <= new Date()) {
                return res.status(400).json({
                    message: "The reminder time must be in the future."
                });
            }

            const [result] = await db.execute(
                `INSERT INTO notifications
                 (user_id, message, scheduled_at, status)
                 VALUES (?, ?, ?, 'scheduled')`,
                [user_id, message, scheduledDate]
            );

            res.status(201).json({
                message: "Reminder scheduled successfully!",
                notification_id: result.insertId,
                scheduled_at: scheduledDate
            });
        } catch (error) {
            console.error("Reminder scheduling error:", error.message);
            res.status(500).json({
                message: "Could not schedule the reminder."
            });
        }
    }
);

/* Deliver reminders when their scheduled time arrives */
setInterval(async () => {
    try {
        const [dueReminders] = await db.execute(
            `SELECT notification_id
             FROM notifications
             WHERE scheduled_at IS NOT NULL
               AND scheduled_at <= NOW()
               AND (status = 'scheduled' OR status = 'pending')`
        );

        for (const reminder of dueReminders) {
            await db.execute(
                `UPDATE notifications
                 SET status = 'unread', scheduled_at = NULL
                 WHERE notification_id = ?
                   AND scheduled_at IS NOT NULL
                   AND scheduled_at <= NOW()`,
                [reminder.notification_id]
            );
        }
    } catch (error) {
        console.error("Reminder delivery error:", error.message);
    }
}, 15000);


/* Link a parent account to a student */
app.post(
    "/parent-student-links",
    verifyToken,
    allowRoles("admin"),
    async (req, res) => {
        try {
            const { parent_id, student_id } = req.body;

            if (!parent_id || !student_id) {
                return res.status(400).json({
                    message: "parent_id and student_id are required."
                });
            }

            const [users] = await db.execute(
                `SELECT user_id, role
                 FROM users
                 WHERE user_id IN (?, ?)`,
                [parent_id, student_id]
            );

            const parent = users.find(
                user => user.user_id === Number(parent_id)
            );
            const student = users.find(
                user => user.user_id === Number(student_id)
            );

            if (
                !parent ||
                parent.role !== "parent" ||
                !student ||
                student.role !== "student"
            ) {
                return res.status(400).json({
                    message: "Please provide a valid parent ID and student ID."
                });
            }

            await db.execute(
                `INSERT INTO parent_student_links (parent_id, student_id)
                 VALUES (?, ?)`,
                [parent_id, student_id]
            );

            res.status(201).json({
                message: "Parent linked to student successfully!"
            });
        } catch (error) {
            if (error.code === "ER_DUP_ENTRY") {
                return res.status(409).json({
                    message: "This parent is already linked to this student."
                });
            }

            console.error("Parent-student linking error:", error.message);
            res.status(500).json({
                message: "Could not link parent to student."
            });
        }
    }
);

/* View parent-student links (administrators only) */
app.get(
    "/parent-student-links",
    verifyToken,
    allowRoles("admin"),
    async (req, res) => {
        try {
            const [links] = await db.execute(
                `SELECT
                    psl.link_id,
                    psl.parent_id,
                    p.first_name AS parent_firstname,
p.surname AS parent_surname,
psl.student_id,
s.first_name AS student_firstname,
s.surname AS student_surname
                 FROM parent_student_links psl
                 JOIN users p ON psl.parent_id = p.user_id
                 JOIN users s ON psl.student_id = s.user_id
                 ORDER BY psl.link_id DESC`
            );

            res.json({
                total: links.length,
                links
            });
        } catch (error) {
            console.error("Parent-student retrieval error:", error.message);
            res.status(500).json({
                message: "Could not retrieve parent-student links."
            });
        }
    }
);


// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
