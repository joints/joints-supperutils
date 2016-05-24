var gulp = require('gulp');
var config = require('../config');

Object.keys(config.tasklines).forEach(function(tl){
  var tlcfg = config.tasklines[tl];

  var tasks = [];

  if(tlcfg.browserify){
    tasks.push('browserify-' + tl);
  }

  if(tlcfg.markup){
    tasks.push('markup-' + tl);
  }

  gulp.task('build-' + tl, tasks);
});