import { Request } from 'express';
import { StaffRole } from '../database/db.service';
export declare const adminApiRouter: import("express-serve-static-core").Router;
export interface AuthenticatedAdminRequest extends Request {
    adminUser?: {
        id: string;
        email: string;
        fullName: string;
        role: StaffRole;
    };
}
