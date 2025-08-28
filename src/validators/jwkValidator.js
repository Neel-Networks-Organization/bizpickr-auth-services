import Joi from 'joi';

export const jwkSchemas = {
  getJWKByKid: Joi.object({
    params: Joi.object({
      kid: Joi.string().required(),
    }),
  }),
};

export const { getJWKByKid } = jwkSchemas;

export default jwkSchemas;
