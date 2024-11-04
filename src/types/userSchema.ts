// src/utils/userSchema.ts

import { loadExtendedSchema } from '../utils/userSchema';

const loadUserSchema = loadExtendedSchema();


// User type definition
export type User = ReturnType<typeof loadUserSchema>;
