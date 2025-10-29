import type { SignUp } from "@/features/auth/schemas/sign-up.schema";

import { db } from "../client";
import { users } from "../schema";

export class UserDao {
  /**
   * @description Creates a new user.
   * @param user - The user to create.
   * @returns The created user.
   */
  static async create(user: SignUp) {
    const [insertedUser] = await db.insert(users).values(user).returning();

    // The user couldn't be created.
    if (!insertedUser) return null;

    const { password, ...userWithoutPassword } = insertedUser;

    return userWithoutPassword;
  }

  /**
   * @description Finds a user by ID.
   * @param id - The user ID.
   * @returns The user.
   */
  static async findById(id: string) {
    return db.query.users.findFirst({
      columns: {
        password: false,
      },
      where: (users, { eq }) => eq(users.id, id),
    });
  }

  /**
   * @description Finds a user by username.
   * @param username - The username to find.
   * @returns The user.
   */
  static async findByUsername(username: string) {
    return db.query.users.findFirst({
      where: (users, { eq }) => eq(users.username, username),
    });
  }

  /**
   * @description Checks if a username is taken.
   * @param username - The username to check.
   * @returns True if the username is taken, false otherwise.
   */
  static async isUsernameTaken(username: string) {
    return db.query.users.findFirst({
      columns: {
        id: true,
      },
      where: (users, { eq }) => eq(users.username, username),
    });
  }

  /**
   * @description Checks if an user exists.
   * @param id - The user ID.
   * @returns True if the user exists, false otherwise.
   */
  static async exists(id: string) {
    const user = await db.query.users.findFirst({
      columns: {
        id: true,
      },
      where: (users, { eq }) => eq(users.id, id),
    });

    return user !== null;
  }
}
