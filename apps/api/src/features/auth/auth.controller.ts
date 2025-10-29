import bcrypt from "bcryptjs";
import type { Context } from "hono";
import z from "zod";

import { UserDao } from "@/database/dao/user.dao";

import { JwtService } from "@/core/services/jwt.service";
import { ApiResponse } from "@/core/utils/api-response";

import { loginSchema } from "./schemas/login.schema";
import { signUpSchema } from "./schemas/sign-up.schema";

export class AuthController {
  /**
   * @description Signs up a new user.
   * @param c - The context.
   * @returns The response.
   */
  static async signUp(c: Context) {
    const body = await c.req.json();
    const formData = signUpSchema.safeParse(body);

    // The form data is invalid.
    if (!formData.success) {
      return ApiResponse.failure(c, {
        status: 400,
        data: z.treeifyError(formData.error).properties,
      });
    }

    const isUsernameTaken = await UserDao.isUsernameTaken(
      formData.data.username,
    );

    // The username is already taken.
    if (isUsernameTaken) {
      return ApiResponse.failure(c, {
        status: 400,
        data: { username: "El nombre de usuario ya está en uso" },
      });
    }

    // Hash the password.
    const passwordHash = bcrypt.hashSync(formData.data.password, 10);

    // Create the user.
    const user = await UserDao.create({
      username: formData.data.username,
      password: passwordHash,
    });

    if (!user) {
      return ApiResponse.error(c, {
        status: 500,
        message: "Error al crear el usuario",
      });
    }

    // Generate the JWT token and set the cookie.
    const token = await JwtService.generate(user.id);
    JwtService.setTokenCookie(c, token);

    return ApiResponse.success(c, {
      status: 201,
      data: user,
    });
  }

  /**
   * @description Logs in a user.
   * @param c - The context.
   * @returns The response.
   */
  static async login(c: Context) {
    const body = await c.req.json();
    const formData = loginSchema.safeParse(body);

    // The form data is invalid.
    if (!formData.success) {
      return ApiResponse.failure(c, {
        status: 400,
        data: z.treeifyError(formData.error).properties,
      });
    }

    const user = await UserDao.findByUsername(formData.data.username);

    const passwordMatch =
      user && bcrypt.compareSync(formData.data.password, user.password);

    // The user doesn't exist or the credentials are incorrect.
    if (!user || !passwordMatch) {
      return ApiResponse.error(c, {
        status: 400,
        message: "Credenciales incorrectas",
      });
    }

    const { password, ...userWithoutPassword } = user;

    // Generate the JWT token and set the cookie.
    const token = await JwtService.generate(user.id);
    JwtService.setTokenCookie(c, token);

    return ApiResponse.success(c, {
      status: 200,
      data: userWithoutPassword,
    });
  }

  /**
   * @description Gets the current user.
   * @param c - The context.
   * @returns The response.
   */
  static async me(c: Context) {
    const payload = JwtService.getPayload(c);
    const user = await UserDao.findById(payload.sub);

    // The user doesn't exist.
    if (!user) {
      return ApiResponse.error(c, {
        status: 401,
        message: "Usuario no encontrado",
      });
    }

    return ApiResponse.success(c, {
      status: 200,
      data: user,
    });
  }

  /**
   * @description Logs out an user.
   * @param c - The context.
   * @returns The response.
   */
  static async logout(c: Context) {
    JwtService.clearTokenCookie(c);

    return ApiResponse.success(c, {
      status: 200,
      data: null,
    });
  }
}
