/* eslint-disable @typescript-eslint/no-misused-promises */
import StatusCodes from "http-status-codes";
import { Request, Response, Router } from "express";
import bcrypt from "bcryptjs";
import { paramMissingError, IRequest } from "@shared/constants";
import knex from "knex";
import jwt from "jsonwebtoken";
import cities from "./cities.json";
import { STATUS_CODES } from "http";

const pg = knex({
  client: "pg",
  connection: process.env.DATABASE,
  searchPath: ["knex", "public"],
});
const router = Router();
const { BAD_REQUEST, CREATED, OK } = StatusCodes;

const secret = "fajdfhajk";

/******************************************************************************
 *                      Get All Users - "GET /api/users/all"
 ******************************************************************************/

interface SignUpProps extends Request {
  body: {
    username: string;
    password: string;
  };
}

router.post("/sign-up", (req: SignUpProps, res: Response) => {
  const { username, password } = req.body;

  // Hash Password
  bcrypt.genSalt(10, function (err, salt) {
    bcrypt.hash(password, salt, async function (err, hash) {
      // Store hash in your password DB.
      await pg("users").insert({ username: username, pass: hash });
    });
  });

  return res.status(OK).json({ message: "Sign up successfuls" });
});

router.post("/sign-in", async (req: SignUpProps, res: Response) => {
  const { username, password } = req.body;

  const user = await pg("users").where({ username });
  if (user.length === 0) {
    return res.status(BAD_REQUEST).json({ message: "No user found!" });
  }
  bcrypt.compare(password, user[0].pass, function (err, result) {
    if (!result) {
      return res.status(BAD_REQUEST).json({ message: "Wrong Password" });
    } else {
      const token = jwt.sign({ username }, secret);

      return res.status(OK).json({ message: "Logged In!", token });
    }
  });
});

interface Props extends Request {
  body: {
    token: string;
  };
}

router.post("/get-cities", async (req: Props, res: Response) => {
  const { token } = req.body;

  jwt.verify(token, secret, function (err, decoded) {
    // err
    if (err) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ message: "Please log in!" });
    }
    // decoded undefined
    return res.status(OK).json(cities);
  });
});

export default router;
