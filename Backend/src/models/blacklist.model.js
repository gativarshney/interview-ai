const mongoose = require("mongoose");

const blacklistTokenSchema = new mongoose.Schema(
  {
    token: {
      type: String,
      required: [true, "Token is required to blacklist"],
      unique: true,
      index: true,
    },
    // Access tokens live for 1 day, so a blacklist entry is worthless after
    // that. The TTL index lets Mongo reclaim the rows instead of growing the
    // collection forever (every authenticated request queries it).
    expiresAt: {
      type: Date,
      required: true,
      default: () => new Date(Date.now() + 24 * 60 * 60 * 1000),
    },
  },
  {
    timestamps: true,
  },
);

blacklistTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const tokenBlacklistModel = mongoose.model("blacklistTokens", blacklistTokenSchema)

module.exports = tokenBlacklistModel
