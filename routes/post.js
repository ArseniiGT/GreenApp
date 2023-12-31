const express = require('express');
const router = express.Router();
const tr = require('transliter');

const models = require('../models');
const config = require('../config');

// GET for add
router.get('/edit/:id', async (req, res, next) => {
  const { userId, userLogin, userRole } = req.session;
  const id = req.params.id.trim().replace(/ +(?= )/g, '');

  if (!userId || !userLogin) {
    res.redirect('/');
    return;
  }

  try {
    const post = await models.Post.findById(id).populate('uploads');

    const success = post.owner.toString() === userId || userRole === 'admin';

    if (!post || !success) {
      const err = new Error('Not Found');
      err.status = 404;
      next(err);
      return;
    }

    res.render('post/edit', {
      post,
      user: {
        id: userId,
        login: userLogin
      },
      siteName: `Plan's edit — ${config.SITE_NAME}`
    });
  } catch (error) {
    console.log(error);
  }
});

// GET for add
router.get('/add', async (req, res) => {
  const userId = req.session.userId;
  const userLogin = req.session.userLogin;

  if (!userId || !userLogin) {
    res.redirect('/');
  } else {
    try {
      const post = await models.Post.findOne({
        owner: userId,
        status: 'draft'
      });

      if (post) {
        res.redirect(`/post/edit/${post.id}`);
      } else {
        const post = await models.Post.create({
          owner: userId,
          status: 'draft'
        });
        res.redirect(`/post/edit/${post.id}`);
      }
    } catch (error) {
      console.log(error);
    }
    // res.render('post/edit', {
    //   user: {
    //     id: userId,
    //     login: userLogin
    //   }
    // });
  }
});

// POST is add
router.post('/add', async (req, res) => {
  const { userId, userLogin, userRole } = req.session;

  if (!userId || !userLogin) {
    res.redirect('/');
  } else {
    const title = req.body.title.trim().replace(/ +(?= )/g, '');
    const body = req.body.body.trim();
    const isDraft = !!req.body.isDraft;
    const postId = req.body.postId;
    const url = `${tr.slugify(title)}-${Date.now().toString(36)}`;

    if (!title || !body) {
      const fields = [];
      if (!title) fields.push('title');
      if (!body) fields.push('body');

      res.json({
        ok: false,
        error: 'Please fill in all the fields!',
        fields,
      });
    } else if (title.length < 3 || title.length > 64) {
      res.json({
        ok: false,
        error: "Title's length from 3 to 64 letters",
        fields: ['title']
      });
    } else if (body.length < 3) {
      res.json({
        ok: false,
        error: 'Text length must be more than 3 letters!',
        fields: ['body']
      });
    } else if (!postId) {
      res.json({
        ok: false
      });
    } else {
      const postStatus = userRole === 'admin' ? 'published' : 'moderated';
      try {
        // const post = await models.Post.findOneAndUpdate(
        //   {
        //     _id: postId
        //     // owner: userId
        //   },
        //   {
        //     title,
        //     body,
        //     url,
        //     owner: userId,
        //     status: isDraft ? 'draft' : postStatus
        //   },
        //   { new: true }
        // );

        const post = await models.Post.findOne({
          _id: postId
        });

        if (!post) {
          res.json({
            ok: false,
            error: 'Plan not found!'
          });
          return;
        }

        if (!(post.owner.toString() === userId || userRole === 'admin')) {
          res.json({
            ok: false,
            error: 'Post is not yours!!'
          });
          return;
        }

        post.title = title;
        post.body = body;
        post.url = url;
        post.owner = userId;
        post.status = isDraft ? 'draft' : postStatus;

        await post.save();

        res.json({
          ok: true,
          post
        });

        ///
      } catch (error) {
        res.json({
          ok: false
        });
      }
    }
  }
});

module.exports = router;
