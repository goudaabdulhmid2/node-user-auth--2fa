module.exports = (user) => {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    twoFactorEnabled: user.twoFactorEnabled,
  };
};
