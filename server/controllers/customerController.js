const Customer = require("../models/Customer");
const mongoose = require("mongoose");
const multer = require('multer');
const fs = require("fs");
const upload = multer({dest:"uploads/"});

exports.homepage = async (req, res) => {
  try {
    const locals = {
      title: 'CMS',
      description: 'Construction Management System',
    };

    const messages = await req.flash('info');

    res.render('index', {
      locals,
      customers,
      current: page,
      pages: Math.ceil(count / perPage),
      messages,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
};

exports.about = async (req, res) => {
  const locals = {
    title: 'About',
    description: ' Construction Management System',
  };

  try {
    res.render('about', locals);
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
};

exports.addCustomer = (req, res) => {
  const locals = {
    title: "Add New Customer",
    description: " Construction Management System",
  };

  res.render("customer/add", locals);
};

exports.view = async (req, res) => {
  try {
    const customer = await Customer.findOne({_id:req.params.id});
    if (!customer) {
      res.status(404).send("Customer not found.");
      return;
    }

    const locals = {
      title: "View Customer Data",
      description: "Construction Management System",
    };

    res.render('customer/view', { 
      locals, customer });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
};

exports.edit = async (req, res) => {
  try {
    const customer = await Customer.findOne({_id:req.params.id});
    if (!customer) {
      res.status(404).send("Customer not found.");
      return;
    }

    const locals = {
      title: "Edit Customer Data",
      description: "Construction Management System",
    };

    res.render('customer/edit', { locals, customer });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
};
exports.editPost = async (req, res) => {
  try {
    await  Customer.findByIdAndUpdate(req.params.id,{
      firstName:req.body.firstName,
      lastName:req.body.lastName,
      tel:req.body.tel,
      email:req.body.email,
      details:req.body.details,
    })
    res.redirect('/secrets')
  } catch (error) {
    console.log(error);
  }
};
exports.deleteCustomer = async (req, res) => {
  try {
    await Customer.deleteOne({_id: req.params.id})
    res.redirect('/secrets')
  } catch (error) {
    console.log(error);
  }
};

