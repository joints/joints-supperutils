'use strict';

var gulp = require('gulp');

var config = require('../config');

Object.keys(config.tasklines).forEach(function(tl){
  var tlConfig = config.tasklines[tl];

  var tasks = ["build-" + tl];

  gulp.task(tl, tasks);
});