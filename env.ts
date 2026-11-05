import { boolean, defineEnv } from "void/env";

export default defineEnv({
  /**
   * 僅供本機整合測試：允許 /api/check 連到 localhost、私有位址與任意連接埠。
   * 只在開發伺服器（import.meta.env.DEV）生效，正式環境即使設定也無效。
   */
  DEV_ALLOW_PRIVATE_TARGETS: boolean().default(false),
});
