// src/types/user.ts

//export the default user type with the auth.schema.options

import { userSchemaOptions } from "../utils/options";

const User = userSchemaOptions();

export type User = ReturnType<typeof User>;