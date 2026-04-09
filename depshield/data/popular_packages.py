"""Top 200 npm packages by weekly download count.

Used as the reference set for typosquatting distance calculations.
"""

TOP_PACKAGES: list[str] = [
    # Core / runtime
    "lodash", "chalk", "request", "commander", "express",
    "moment", "react", "async", "bluebird", "debug",
    "fs-extra", "glob", "mkdirp", "underscore", "uuid",
    "yargs", "colors", "minimist", "body-parser", "through2",
    "rimraf", "semver", "webpack", "axios", "inquirer",
    # Testing & quality
    "mocha", "eslint", "jest", "chai", "sinon",
    "prettier", "typescript", "babel-core", "babel-loader", "babel-preset-env",
    "nyc", "istanbul", "karma", "jasmine", "tape",
    # React ecosystem
    "react-dom", "react-router", "react-redux", "redux", "prop-types",
    "react-router-dom", "styled-components", "next", "gatsby", "create-react-app",
    "react-scripts", "react-native", "material-ui", "@mui/material", "antd",
    # Build tools
    "webpack-cli", "webpack-dev-server", "rollup", "gulp", "grunt",
    "parcel", "esbuild", "vite", "turbo", "nx",
    "babel-cli", "@babel/core", "@babel/preset-env", "@babel/preset-react", "@babel/preset-typescript",
    # Node essentials
    "dotenv", "cors", "cookie-parser", "morgan", "helmet",
    "http-proxy-middleware", "jsonwebtoken", "bcrypt", "bcryptjs", "passport",
    "mongoose", "sequelize", "knex", "pg", "mysql2",
    "redis", "ioredis", "amqplib", "socket.io", "ws",
    # Utility
    "lodash.get", "lodash.merge", "lodash.clonedeep", "lodash.debounce", "lodash.throttle",
    "ramda", "rxjs", "immutable", "date-fns", "dayjs",
    "classnames", "clsx", "nanoid", "shortid", "cuid",
    # HTTP / API
    "node-fetch", "got", "superagent", "request-promise", "needle",
    "cheerio", "puppeteer", "playwright", "selenium-webdriver", "cypress",
    # File / stream
    "form-data", "multer", "busboy", "formidable", "archiver",
    "tar", "unzipper", "csv-parser", "xlsx", "pdf-lib",
    # CLI / terminal
    "chalk", "ora", "yargs-parser", "meow", "boxen",
    "listr", "progress", "cli-table3", "terminal-kit", "figlet",
    # Config
    "config", "convict", "nconf", "rc", "cosmiconfig",
    "cross-env", "env-cmd", "dotenv-expand", "dotenv-safe", "envalid",
    # Logging
    "winston", "pino", "bunyan", "log4js", "loglevel",
    "morgan", "debug", "signale", "consola", "npmlog",
    # Validation / schema
    "joi", "yup", "ajv", "zod", "validator",
    "class-validator", "express-validator", "superstruct", "io-ts", "runtypes",
    # Auth / crypto
    "passport-jwt", "passport-local", "oauth", "grant", "simple-oauth2",
    "crypto-js", "tweetnacl", "libsodium-wrappers", "argon2", "scrypt-js",
    # CSS / style
    "postcss", "autoprefixer", "tailwindcss", "sass", "less",
    "css-loader", "style-loader", "mini-css-extract-plugin", "cssnano", "stylelint",
    # Vue / Angular / Svelte
    "vue", "@vue/cli-service", "vuex", "vue-router", "nuxt",
    "@angular/core", "@angular/cli", "@angular/common", "@angular/router", "@angular/forms",
    "svelte", "sveltekit", "@sveltejs/kit", "solid-js", "lit",
    # Misc popular
    "sharp", "jimp", "canvas", "d3", "three",
    "luxon", "qs", "query-string", "url-parse", "path-to-regexp",
    "micromatch", "picomatch", "fast-glob", "chokidar", "watchman",
]
