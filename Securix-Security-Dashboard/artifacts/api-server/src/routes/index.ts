import { Router, type IRouter } from "express";
import healthRouter from "./health";
import securixRouter from "./securix";

const router: IRouter = Router();

router.use(healthRouter);
router.use(securixRouter);

export default router;
