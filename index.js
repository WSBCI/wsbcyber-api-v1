import express from "express";
import mysql from "mysql";
import cors from "cors";
import jwt, { decode } from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import multer from "multer";
import fileUpload from "express-fileupload";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import dotenv from "dotenv";
import { put, list } from "@vercel/blob";

const salt = 10;
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(fileUpload({
  uriDecodeFileNames: true,
}))

const port = process.env.PORT || 8081;

const hostname = process.env.DB_HOSTNAME_URL;
const username = process.env.DB_USERNAME;
const password = process.env.DB_PASSWORD;
const database = process.env.DB_DATABASE_NAME;
const databasePort = process.env.DB_DATABASE_PORT;

const pool = mysql.createPool({
  host: hostname,
  user: username,
  password: password,
  database: database,
  port: databasePort
});

// ? Pool connection
function getConnectionFromPool (callback) {
  pool.getConnection((err, db) => {
    if (err) {
      console.error('Error getting database connection: ', err);
      callback(err, null);
      return;
    }
    callback(null, db);
  })
}

const verifyUser = (req, res, next) => {
  const tokenWithBearer = req.headers.authorization;
  const token = tokenWithBearer.slice(7);

  if (!token) {
    return res.json({
      status: "Error",
      message: "Error permission should provided token!",
    });
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      if (err) {
        return res.json({ status: "Error", message: err.message });
      } else {
        req.username = decoded.username;
        req.userId = decoded.userId;
        req.role = decoded.role;
        return next();
      }
    });
  }
};

const checkDuplicatUsername = (req, res, next) => {
  if (req.body.username === null) return next();

  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = "SELECT * FROM users WHERE `username` = ?";
    db.query(sql, [req.body.username], (err, data) => {
      db.release();

      if (err)
        return res.json({
          status: "Error",
          message: "Error collecting duplicate username",
        });
      if (data.length > 0) {
        if (req.params.id && data[0].id.toString() === req.params.id) {
          return next();
        }
        return res.json({
          status: "Error",
          message: "Error duplicating username",
        });
      } else return next();
    });
  });
};

const checkDuplicatEmail = (req, res, next) => {
  if (req.body.email === null) return next();

  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = "SELECT * FROM users WHERE `email` = ?";
    db.query(sql, [req.body.email], (err, data) => {
      db.release();

      if (err)
        return res.json({
          status: "Error",
          message: "Error collecting duplicate email",
        });
      if (data.length > 0) {
        if (req.params.id && data[0].id.toString() === req.params.id) {
          return next();
        }
        return res.json({
          status: "Error",
          message: "Error duplicating email",
        });
      } else return next();
    });
  });
};

const checkDuplicatContributorSameBlog = (req, res, next) => {
  if (!req.params.id)
    return res.json({ status: "Error", message: "Error not found blog" });
  if (!req.userId)
    return res.json({ status: "Error", message: "Error permission not exist" });

  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = "SELECT * FROM contributors WHERE `blog_id` = ?";
  
    db.query(sql, req.params.id, (err, data) => {
      db.release();

      if (err)
        return res.json({ status: "Error", message: "Error internal server" });
      if (!data)
        return res.json({ status: "Error", message: "Error not found blog" });
      // cek jika belum ada contributor dalam blog
      if (data.length === 0) {
        req.isContributorExist = false;
        return next();
      }
  
      // cek apakah data user contributor sama dengan admin pengubah blog
      if (data[0].user_id === req.userId) {
        req.isContributorExist = true;
      } else {
        req.isContributorExist = false;
      }
      return next();
    });
  });
};

const slugify = (text) => {
  return text
    .toString()
    .toLowerCase()
    .replace(/\s+/g, "-") // mengganti spasi dengan -
    .replace(/[^\w\-]+/g, "") // menghapus karakter yang bukan kata
    .replace(/\-\-+/g, "-") // mengganti dua atau lebih tanda - dengan satu tanda -
    .replace(/^-+/, "") // menghapus tanda - yang berada di awal kalimat
    .replace(/-+$/, ""); //menghapus tanda - yang berada di akhir kalimat
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

//TODO: upload cover to blob vercel
const uploadBlob = async (req, res, next) => {
  const form = await req.files;
  const formFile = form["file"];
  const ext = path.extname(formFile.name);
  
  if (ext !== '.jpg' && ext !== '.png' && ext !== '.jpeg') {
    return res.json({status: 'Error', message: 'Only jpg, jpeg and png format is allowed'})
  }
  const filename = `${Date.now()}_${formFile.name}`;
  const buffer = new Blob([formFile.data], { type: formFile.mimetype });
  try {
    const blob = await put(filename, buffer, {
      access: 'public',
    });
  
    req.imageUrl = blob.url;
    req.filename = formFile.name;
    return next();
  } catch (error) {
    res.json({
      status: "Error",
      message: `Error: ${error}. Upload image failed`,
      url: 'none',
      filename: 'none.jpg',
    });
  }
};
app.post("/upload", uploadBlob, (req, res) => {
  res.json({
    status: "Success",
    message: "File uploaded successfully",
    url: req.imageUrl,
    filename: req.filename,
  });
});

app.get('/api/download', async (req, res) => {
  const { blobs } = await list();
  return res.json(blobs);
})

//TODO: create new user
app.post("/register", checkDuplicatUsername, checkDuplicatEmail, (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql =
      "INSERT INTO users (`username`, `password`, `email`, `image`, `role`) VALUES (?)";
  
    // cek dilarang membuat user dengan role super admin
    if (req.body.role === "superadmin") {
      db.release();
      res.json({ status: "Error", message: "Error creating new user" })
    };
  
    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
      if (err) {
        db.release();
        return res.json({
          status: "Error",
          message: "Error for hassing password",
        })
      };
  
      // membuat link untuk gambar profil dari nilai nama
      const nameImage = req.body.username.split(" ");
      const joinNameImage = nameImage.join("+");
      let image = `https://ui-avatars.com/api/?name=${joinNameImage}&background=a80000&color=fff&bold=true&font-size=0.4`;
  
      const values = [
        req.body.username,
        hash,
        req.body.email,
        image,
        req.body.role,
      ];
      db.query(sql, [values], (err, result) => {
        db.release();

        if (err) {
          return res.json({
            status: "Error",
            message: "Error creating new user",
          });
        }
        return res.json({ status: "Success" });
      });
    });
  });
});

// TODO: login account user
app.post("/login", (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = "SELECT * FROM users WHERE `email` = ?";
  
    db.query(sql, [req.body.email], (err, data) => {
      db.release();
      if (err)
        return res.json({ status: "Error", message: "Error internal server" });
      if (data.length > 0) {
        //? cek apakah password yang dimasukkan sesuai
        bcrypt.compare(
            req.body.password.toString(), data[0].password, (err, response) =>{
                if (err) return res.json({ status: 'Error', message: 'Error internal server' });
                if (response) {
        const username = data[0].username;
        const token = jwt.sign(
          { username, userId: data[0].id, role: data[0].role },
          "jwt-secret-key",
          {
            expiresIn: "1d",
          }
        );
        return res.json({ status: "Success", token: token });
                } else {
                    return res.json({ status: 'Error', message: 'Error password not match' });
                }
            }
        );
      } else {
        return res.json({ status: "Error", message: "Error not found user" });
      }
    });
  });
});

// TODO: get own user account
app.get("/users/me", verifyUser, (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql =
      "SELECT id, username, email, role, image FROM users WHERE `id` = ?";
  
    db.query(sql, [req.userId], (err, data) => {
      db.release();
      if (err) return res.json({ status: "Error", message: err.message });
      return res.json({ status: "Success", data: data });
    });
  });
});

// TODO: get all users
app.get("/users", verifyUser, (req, res) => {
  // Author tidak diperbolehkan melihat profil user
  if (req.role === "author") {
    return res.json({
      status: "Error",
      message: "Error permission!",
      data: null,
    });
  }

  // mengatur pagination jika page bernilai 0 dan negatif maka tidak ada data
  if (req.query.page <= 0)
    return res.json({
      status: "Error",
      message: "Internal server error",
      data: null,
      totalPages: 0,
    });
  const page = parseInt(req.query.page) || 1;
  const limit = 15; // mengatur maksimal data yang diambil
  const offset = (page - 1) * limit; // untuk query mengatur mulai darimana data diambil
  const search = req.query.query || "";
  const query = "%" + search + "%";

  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
  
    const values = [req.userId, query, limit, offset];
    const sql =
      'SELECT id, username, email, role, created_at AS createdAt FROM users WHERE (`id` != ? AND `role` != "superadmin") AND username LIKE ? LIMIT ? OFFSET ?';
  
    db.query(sql, values, (err, data) => {
      if (err) {
        db.release();
        return res.json({
          status: "Error",
          message: "Error collecting data users",
          data: null,
        })
      };
      
      const totalSql =
        'SELECT COUNT(*) AS total FROM users WHERE `role` != "superadmin" AND username LIKE ?';
      db.query(totalSql, query, (error, totalCount) => {
        db.release();

        if (error)
          return res.json({
            status: "Error",
            message: "Internal server error",
            data: null,
          });
  
        const total = totalCount[0].total;
        const totalPages = Math.ceil(total / limit);
        return res.json({
          status: "Success",
          data: data,
          totalPages: totalPages,
          countData: total,
        });
      });
    });
  });
});

// TODO: get detail user
app.get("/users/:id", verifyUser, (req, res) => {
  // Author tidak diperbolehkan melihat profil user selain profil pribadi
  if (req.role === "author" && req.userId.toString() !== req.params.id) {
    return res.json({
      status: "Error",
      message: "Error permission!",
      data: null,
    });
  }
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
  
    const sql = "SELECT id, username, email, role FROM users WHERE `id` = ?";
  
    db.query(sql, [req.params.id], (err, data) => {
      db.release();

      if (err)
        return res.json({
          status: "Error",
          message: "Error collecting data users",
          data: null,
        });
      // admin lain tidak dapat melihat profil super admin
      if (req.role !== "superadmin" && data[0].role === "superadmin") {
        return res.json({
          status: "Error",
          message: "Error internal server",
          data: null,
        });
      }
      return res.json({ status: "Success", data: data });
    });
  });
});

// TODO: update detail user account
app.post(
  "/users/:id",
  verifyUser,
  checkDuplicatUsername,
  checkDuplicatEmail,
  (req, res) => {
    // author tidak diperbolehkan melakukan update profil yang bukan miliknya dan tidak bisa melakukan perubahan role
    if (req.role === "author" && req.userId.toString() !== req.params.id) {
      if (req.body.role && ["admin", "superadmin"].includes(req.body.role)) {
        return res.json({
          status: "Error",
          message: "Error permission author cannot change role!",
        });
      }
      return res.json({
        status: "Error",
        message: "Error permission author cannot update profile!",
      });
    }
    // admin tidak diperkenankan untuk mengubah role menjadi super admin
    if (req.role === "admin" && req.body.role === "superadmin") {
      return res.json({
        status: "Error",
        message: "Error permission admin to change role!",
      });
    }
    getConnectionFromPool((err, db) => {
      if (err) {
        return res.json({
          status: "Error",
          message: "Error connecting to database",
          data: null,
        });
      }
      // melakukan cek role user yang akan di edit
      const checkSql = "SELECT role FROM users WHERE `id` = ?";
      db.query(checkSql, req.params.id, (checkErr, check) => {
        if (checkErr) {
          db.release();
          return res.json({ status: "Error", message: "Error internal server" })
        };
        if (!check[0].role){
          db.release();
          return res.json({ status: "Error", message: "Error internal server" })
        };
        // cek apakah role yang melakukan pengeditan adalah super admin
        if (req.role === "superadmin") {
          // cek apakah nilai id user login sama dengan id user yang di edit
          if (req.params.id !== req.userId.toString()) {
            // cek apakah req body role adalah super admin (user akan mengedit user superadmin lain)
            if (req.body.role === "superadmin") {
              db.release();
              return res.json({
                status: "Error",
                message:
                  "Error permission change another user superadmin profil!",
              });
            }
            // cek apakah terdapat password dan user yang di edit adalah superadmin
            if (req.body.password && check[0].role === "superadmin") {
              db.release();
              return res.json({
                status: "Error",
                message:
                  "Error permission change another user superadmin password!",
              });
            }
          }
        }
  
        const userId = req.params.id;
        // jika username, email, role ada maka itu yang akan di update
        if (req.body.username && req.body.email && req.body.role) {
          const sql =
            "UPDATE users SET `username` = ?, `email` = ?, `role` = ? WHERE `id` = ?";
          const values = [
            req.body.username,
            req.body.email,
            req.body.role,
            userId,
          ];
          db.query(sql, values, (err, result) => {
            db.release();

            if (err)
              return res.json({
                status: "Error",
                message: "Error updating profil user",
              });
            return res.json({ status: "Success" });
          });
        } else {
          // perubahan untuk password terpisah
          const sql = "UPDATE users SET `password` = ? WHERE `id` = ?";
          bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
            if (err){
              db.release();
              return res.json({
                status: "Error",
                message: "Error for hassing password",
              })
            };
  
            const values = [hash, userId];
            db.query(sql, values, (err, result) => {
              db.release();

              if (err)
                return res.json({
                  status: "Error",
                  message: "Error updating profil user",
                });
              return res.json({ status: "Success" });
            });
          });
        }
      });
    });
  }
);

// TODO: delete user
app.delete("/users/:id", verifyUser, (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    // Author tidak diperbolehkan menghapus profil
    if (req.role === "author") {
      return res.json({ status: "Error", message: "Error permission!" });
    }
  
    const sql = "SELECT * FROM users WHERE `id` = ?";
    db.query(sql, req.params.id, (err, data) => {
      if (err){
        db.release();
        return res.json({ status: "Error", message: "Error internal server" })
      };
      if (data.length > 0) {
        // cek apakah akun yang dipilih merupakan super admin
        if (data[0].role === "superadmin") {
          return res.json({ status: "Error", message: "Error permission" });
        }
        const deleteSql = "DELETE FROM users WHERE `id` = ?";
        db.query(deleteSql, req.params.id, (deleteErr) => {
          db.release();

          if (deleteErr)
            if (err)
              return res.json({
                status: "Error",
                message: "Error deleting profil user",
              });
          return res.json({ status: "Success" });
        });
      } else {
        db.release();
        return res.json({
          status: "Error",
          message: "Error profil user not found",
        });
      }
    });
  });
});

// TODO: get all blogs
app.get("/blogs", (req, res) => {
  // mengatur pagination jika page bernilai 0 dan negatif maka tidak ada data
  if (req.query.page <= 0)
    return res.json({
      status: "Error",
      message: "Internal server error",
      data: null,
      totalPages: 0,
    });
  const page = parseInt(req.query.page) || 1;
  const limit = 15; // mengatur maksimal data yang diambil
  const offset = (page - 1) * limit; // untuk query mengatur mulai darimana data diambil
  const search = req.query.query || "";
  const query = "%" + search + "%";

  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }

    const sql = `
          SELECT
              blogs.id AS id_blog,
              blogs.title AS title,
              blogs.slug AS slug,
              blogs.publish_status AS publishStatus,
              blogs.created_at AS createdAt,
              categories.name AS category,
              users.username AS createdBy
          FROM
          blogs
              JOIN users ON blogs.author_id = users.id
              LEFT JOIN categories ON blogs.category_id = categories.id
          WHERE
              (blogs.title LIKE ? OR categories.name LIKE ? OR users.username LIKE ? OR blogs.publish_status LIKE ?)
              AND (blogs.category_id IS NULL OR blogs.category_id IS NOT NULL)
          ORDER BY
              blogs.created_at DESC
          LIMIT ? OFFSET ?;
      `;
    // query sebanyak 4 bagian untuk judul, kategori, author, dan status publish
    const values = [query, query, query, query, limit, offset];
    db.query(sql, values, (err, data) => {
      if (err) {
        db.release();
        return res.json({
          status: "Error",
          message: "Error collecting data blogs",
          data: null,
          totalPages: 0,
        })
      };
      // mengembalikan nilai category menjadi '' jika bernilai null
      data.forEach((entry) => {
        if (entry.category === null) {
          entry.category = "";
        }
      });
      const totalSql =
        "SELECT COUNT(*) AS total FROM blogs JOIN users ON blogs.author_id = users.id LEFT JOIN categories ON blogs.category_id = categories.id WHERE blogs.title LIKE ? OR categories.name LIKE ? OR users.username LIKE ? OR blogs.publish_status LIKE ?";
      const countVal = [query, query, query, query];
      db.query(totalSql, countVal, (error, totalCount) => {
        db.release();
        
        if (error)
          return res.json({
            status: "Error",
            message: "Internal server error",
            data: null,
            totalPages: 0,
          });
        const total = totalCount[0].total;
        const totalPages = Math.ceil(total / limit);
        return res.json({
          status: "Success",
          data: data,
          totalPages: totalPages,
          countData: total,
        });
      });
    });
  })
});

// TODO: get publish blog
app.get("/blogs/publish", (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = `
          SELECT
          blogs.id AS id_blog,
          blogs.title AS title,
          blogs.slug AS slug,
          blogs.content AS content,
          blogs.cover AS cover,
          blogs.publish_status AS publishStatus,
          blogs.created_at AS createdAt,
          blogs.publish_at AS publishAt,
          categories.name AS category,
          users.username AS createdBy,
          GROUP_CONCAT(contributor_users.username) AS contributors
      FROM
          blogs
          JOIN users ON blogs.author_id = users.id
          LEFT JOIN categories ON blogs.category_id = categories.id
          LEFT JOIN contributors ON blogs.id = contributors.blog_id
          LEFT JOIN users AS contributor_users ON contributors.user_id = contributor_users.id
      WHERE
          blogs.publish_status = "publish"
      GROUP BY
          blogs.id
      ORDER BY
          blogs.publish_at DESC;
      `;
    db.query(sql, (err, data) => {
      db.release();

      if (err)
        return res.json({ status: "Error", message: "Error internal server!" });
      if (data.length < 1)
        return res.json({ status: "Error", message: "Blogs not found!" });
      data.forEach((entry) => {
        if (entry.contributors === null) {
          entry.contributors = [];
        }
        if (entry.contributors.length > 0) {
          const contributors = entry.contributors.split(",");
          entry.contributors = contributors;
        }
      });
      return res.json({ status: "Success", data: data });
    });
  });
});

// TODO: get detail publish blog
app.get("/blogs/publish/:slug", (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = `
          SELECT
          blogs.id AS id_blog,
          blogs.title AS title,
          blogs.slug AS slug,
          blogs.content AS content,
          blogs.cover AS cover,
          blogs.publish_status AS publishStatus,
          blogs.publish_at AS publishAt,
          blogs.created_at AS createdAt,
          categories.name AS category,
          users.username AS createdBy,
          GROUP_CONCAT(contributor_users.username) AS contributors
      FROM
          blogs
          JOIN users ON blogs.author_id = users.id
          LEFT JOIN categories ON blogs.category_id = categories.id
          LEFT JOIN contributors ON blogs.id = contributors.blog_id
          LEFT JOIN users AS contributor_users ON contributors.user_id = contributor_users.id
      WHERE
          blogs.publish_status = "publish" AND blogs.slug = ?
      GROUP BY
          blogs.id
      ORDER BY
          blogs.created_at DESC;
      `;
  
    db.query(sql, req.params.slug, (err, data) => {
      db.release();

      if (err)
        return res.json({ status: "Error", message: "Error internal server!" });
      if (data.length < 1)
        return res.json({ status: "Error", message: "Blogs not found!" });
      data.forEach((entry) => {
        if (entry.contributors === null) {
          entry.contributors = [];
        }
        if (entry.contributors.length > 1) {
          const contributors = entry.contributors.split(",");
          entry.contributors = contributors;
        }
      });
      return res.json({ status: "Success", data: data });
    });
  });
});

// TODO: save blog
app.post("/blogs", verifyUser, (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const isCategory = req.body.category !== "";
    const sql =
      "INSERT INTO blogs (`title`, `slug`, `content`, `cover`, `event_date`, `publish_status`, `author_id`, `category_id`) VALUES (?)";
  
    const titleShort = slugify(req.body.title);
    const slug = titleShort + "&time" + new Date();
  
    let eventDate;
    if (req.body.eventDate === "") {
      eventDate = null;
    } else {
      eventDate = new Date(req.body.eventDate);
    }
  
    const values = [
      req.body.title,
      slug,
      req.body.content || "",
      req.body.cover || "",
      eventDate,
      "draft",
      req.userId,
      isCategory ? req.body.category : null,
    ];
  
    db.query(sql, [values], (err, results) => {
      if (err) {
        db.release();
        return res.json({ status: "Error", message: "Error creating new blog" })
      };
      const sqlSlug = "UPDATE blogs SET `slug` = ? WHERE `id` = ?";
  
      // membuat slug baru dengan modifikasi tambahan id blog
      const blogIdWSB = results.insertId + 23192;
      const newSlug = titleShort + "&uid" + blogIdWSB;
      db.query(sqlSlug, [newSlug, results.insertId], (err, data) => {
        db.release();

        if (err)
          return res.json({
            status: "Success",
            message: "Warning not update slug blog",
            blogSlug: slug,
            blogId: results.insertId,
          });
        return res.json({
          status: "Success",
          blogSlug: newSlug,
          blogId: results.insertId,
        });
      });
    });
  });
});

// TODO: get detail blog
app.get("/blogs/:slug", (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = `SELECT 
              blogs.id AS blogId, 
              blogs.title AS title, 
              blogs.slug AS slug, 
              blogs.content AS content, 
              blogs.cover AS cover, 
              blogs.publish_status AS publishStatus, 
              blogs.event_date AS eventDate, 
              blogs.created_at AS createdAt, 
              blogs.updated_at AS updatedAt, 
              author.username AS author, 
              modified.username AS updatedBy, 
              blogs.category_id AS categoryId, 
              categories.name AS category 
          FROM blogs 
              JOIN users author ON blogs.author_id = author.id 
              LEFT JOIN users modified ON blogs.updated_by = modified.id 
              LEFT JOIN categories ON blogs.category_id = categories.id 
          WHERE slug = ? 
              AND (blogs.category_id IS NULL OR blogs.category_id IS NOT NULL) 
              AND (blogs.updated_by IS NULL OR blogs.updated_by IS NOT NULL);`;
  
    db.query(sql, req.params.slug, (err, dataBlog) => {
      if (err) {
        db.release();
        return res.json({
          status: "Error",
          message: "Error collecting data blog",
        })
      };
      if (dataBlog.length > 0) {
        // mengubah category, updatedBy, eventDate menjadi '' jika bernilai null
        dataBlog.forEach((entry) => {
          if (entry.category === null) {
            entry.category = "";
          }
          if (entry.updatedBy === null) {
            entry.updatedBy = "";
          }
          if (entry.eventDate === null) {
            entry.eventDate = "";
          }
        });
        // fetching data contributors
        const contributorSql =
          "SELECT users.username AS contributor FROM contributors JOIN users ON contributors.user_id = users.id WHERE `blog_id` = ?";
        db.query(
          contributorSql,
          dataBlog[0].blogId,
          (contributorErr, contributor) => {
            db.release();

            if (contributorErr)
              return res.json({
                status: "Error",
                message: "Error collecting contributor blog",
              });
            const contributors = [];
            if (contributor.length > 0) {
              contributor.map((user) => contributors.push(user.contributor));
            }
            return res.json({
              status: "Success",
              data: { blog: dataBlog[0], contributors },
            });
          }
        );
      } else {
        db.release();
        return res.json({
          status: "Error",
          message: "Error not found data blog",
        });
      }
    });
  });
});

// TODO: update detail blog
app.put(
  "/blogs/:id",
  verifyUser,
  checkDuplicatContributorSameBlog,
  (req, res) => {
    getConnectionFromPool((err, db) => {
      if (err) {
        return res.json({
          status: "Error",
          message: "Error connecting to database",
          data: null,
        });
      }
      const isContributorExist = req.isContributorExist;
      const isCategory = req.body.category !== "";
      const sqlAuth = "SELECT author_id FROM blogs WHERE `id` = ?";
      // melakukan pengecekan apakah pengubah blog merupakan author blog juga
      db.query(sqlAuth, req.params.id, (err, result) => {
        if (err) {
          db.release();
          return res.json({
            status: "Error",
            message: "Error proccessing update blog",
          }) 
        };
        if (result[0].author_id) {
          let isAuthUserSame = req.userId === result[0].author_id;
  
          // membuat slug dari nilai title dan modifikasi id blog
          const blogIdWSB = Number(req.params.id) + 23192;
          const slugShort = slugify(req.body.title);
          const newSlug = slugShort + "&uid" + blogIdWSB;
  
          const updatedAt = new Date();
          let eventDate;
          if (req.body.eventDate === "") {
            eventDate = null;
          } else {
            eventDate = new Date(req.body.eventDate);
          }
          // query untuk update blog
          const updatesSql = `UPDATE blogs SET title = ?, slug = ?, content = ?, cover = ?, event_date = ?, updated_at = ?, updated_by = ?,category_id = ? WHERE id = ?`;
          const updatesVal = [
            req.body.title,
            newSlug,
            req.body.content || "",
            req.body.cover || "",
            eventDate,
            updatedAt,
            req.userId,
            isCategory ? req.body.category : null,
            req.params.id,
          ];
          // query untuk menambah kontributor jika ada
          const contributorVal = isAuthUserSame
            ? []
            : [req.userId, req.params.id];
          const contributorSql = `INSERT INTO contributors (user_id, blog_id) VALUES (?)`;
  
          // start transaction
          db.query("START TRANSACTION", (startErr) => {
            if (startErr) {
              db.release();
              return res.json({
                status: "Error",
                message: "Error starting transaction",
              })
            };
  
            // update blog
            db.query(updatesSql, updatesVal, (updateErr, data) => {
              if (updateErr) {
                db.release();
                console.log(updateErr);
                return res.json({
                  status: "Error",
                  message: "Error updating blog",
                });
              }
  
              // cek apakah yang mengedit adalah author (true)
              // cek apakah yang mengedit sudah terdaftar dalam contributor (true)
              // jika keduanya atau salah satu true maka tidak akan dilakukan pendaftaran contributor
              if (!isAuthUserSame && !isContributorExist) {
                db.query(contributorSql, [contributorVal], (contributorErr) => {
                  if (contributorErr) {
                    db.query("ROLLBACK", (rollbackErr) => {
                      if (rollbackErr) {
                        db.release();
                        return res.json({
                          status: "Error",
                          message: "Error rolling back transaction",
                        });
                    }});
                    // return ketika rollback tidak error
                    db.release();
                    return res.json({
                      status: "Error",
                      message: "Error updating blog",
                    });
                  }
                });
              }
  
              // commit transaction
              db.query("COMMIT", (commitErr) => {
                db.release();

                if (commitErr)
                  return res.json({
                    status: "Error",
                    message: "Error commiting transaction",
                  });
                return res.json({
                  status: "Success",
                  blogSlug: newSlug,
                  blogId: result[0].id,
                });
              });
            });
          });
        }
      });
    });
  }
);

// TODO: publish or draft blog
app.post("/blogs/:slug/:action", verifyUser, (req, res) => {
  // action yang diperbolehkan hanyalah draft untuk menjadikan draft dan publish untuk menjadikan publish
  if (req.params.action === "draft" || req.params.action === "publish") {
      getConnectionFromPool((err, db) => {
        if (err) {
          return res.json({
            status: "Error",
            message: "Error connecting to database",
            data: null,
          });
        }
      const sql =
        "UPDATE blogs SET `publish_status` = ?, `publish_at` = ? WHERE `slug` = ?";
      let timeUpdate = null;
      if (req.params.action === "publish") timeUpdate = new Date();
      const values = [req.params.action, timeUpdate, req.params.slug];
  
      db.query(sql, values, (err, data) => {
        db.release();
        if (err)
          return res.json({ status: "Error", message: "Error publish the blog" });
        return res.json({ status: "Success" });
      });
    });
    } else {
      // return jika action selain draft dan publish
      return res.json({ status: "Error", message: "Error internal server" });
    }
});

// TODO: delete blog
app.delete("/blogs/:id", verifyUser, (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = "DELETE FROM blogs WHERE `id` = ?";
  
    db.query(sql, req.params.id, (err, result) => {
      db.release();

      if (err)
        return res.json({ status: "Error", message: "Error deleting blog" });
      return res.json({ status: "Success" });
    });
  });
});

// TODO: get all categories
app.get("/categories", (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = "SELECT * FROM categories";
  
    db.query(sql, (err, data) => {
      db.release();

      if (err)
        return res.json({
          status: "Error",
          message: "Error collecting categories",
        });
      return res.json({ status: "Success", data: data });
    });
  });
});

// TODO: create category
app.post("/categories", verifyUser, (req, res) => {
  if (req.body.name === "" && req.body.description === "") {
    return res.json({ status: "Error", message: "Error creating category" });
  }

  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = "INSERT INTO categories (name, description) VALUES (?)";
    const values = [req.body.name.toLowerCase(), req.body.description];
    
    db.query(sql, [values], (err, data) => {
      db.release();

      if (err) {
        // jika terdapat duplikat category maka akan terjadi error
        if (err.code === "ER_DUP_ENTRY") {
          return res.json({
            status: "Error",
            message: "Error duplicate category found",
          });
        }
        return res.json({ status: "Error", message: "Error creating category" });
      }
      return res.json({ status: "Success" });
    });
  });
});

// TODO: delete category
app.delete("/categories/:id", verifyUser, (req, res) => {
  getConnectionFromPool((err, db) => {
    if (err) {
      return res.json({
        status: "Error",
        message: "Error connecting to database",
        data: null,
      });
    }
    const sql = "DELETE FROM categories WHERE `id` = ?";
  
    db.query(sql, req.params.id, (err, result) => {
      db.release();
      if (err)
        return res.json({ status: "Error", message: "Error deleting category" });
      return res.json({ status: "Success" });
    });
  });
});

app.get("/", (req, res) => {
  console.log("listening /");
  res.status(500).send("Hey API is running 🥳");
});

app.listen(port, () => {
  const name = "WSB Cyber";
  const nameImage = name.split(" ");
  const joinNameImage = nameImage.join("+");

  console.log(joinNameImage);
  console.log("Running...");
});
