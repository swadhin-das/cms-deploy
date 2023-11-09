const mongoose = require('mongoose');

const Schema = mongoose.Schema;
const customerSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  details: String,
  tel: String,
  email: String,
  profileImage: Buffer,
});

module.exports = mongoose.model('Customer', customerSchema);
