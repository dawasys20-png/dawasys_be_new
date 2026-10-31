const pg = require("pg");
pg.types.setTypeParser(1114, (str) =>
  str ? str.replace(" ", "T") + "Z" : null,
); // TIMESTAMP
pg.types.setTypeParser(1184, (str) =>
  str ? str.replace(" ", "T") + "Z" : null,
); // TIMESTAMPTZ
pg.types.setTypeParser(1082, (str) => str); // DATE values are calendar dates, not instants.


const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

module.exports = pool;