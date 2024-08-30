import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from './../src/app.module';
import { CreateUserDto } from 'src/user/dto/create-user.dto';

type signupJwtResponse = {
  FirstName: string;
  Email: string;
  Provider: 'JWT';
  LastName: string | null;
  Id: number;
};

function getCookiesFromHeader(cookies: string[]): {
  [key: string]: string;
} {
  const parsedCookies = {};
  cookies.forEach((cookie) => {
    parsedCookies[cookie.split('=')[0]] = cookie
      .replace(/[A-z]+\=|[0-9]+\=/, '')
      .split(';')[0];
  });
  return parsedCookies;
}

const signupData: CreateUserDto = {
  FirstName: 'Konami',
  Email:
    Math.floor(Math.random() * 1000) +
    'konami@aist.com' +
    Math.floor(Math.random() * 1000),
  Password: 'konamiusGigachad',
};

describe('AppController (e2e)', () => {
  let app: INestApplication;
  let accessToken: string;
  let user: signupJwtResponse;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('/auth/signup (Post) - success', async () => {
    const response = await request(app.getHttpServer())
      .post('/auth/signup')
      .send(signupData)
      .expect(201);

    const { headers, body } = response;

    const cookies = getCookiesFromHeader(
      headers['set-cookie'] as unknown as string[],
    );
    accessToken = cookies.AccessToken;
    user = body;
    return response;
  });

  it('/user/:id (delete) - fail', () => {
    const response = request(app.getHttpServer())
      .delete(`/user/${user.Id}`)
      .set('Accept', 'application/json')
      .set('Authorization', 'Bearer ' + accessToken + 'gjeuir')
      .expect(401);

    return response;
  });

  it('/user/:id (delete) - success', () => {
    const response = request(app.getHttpServer())
      .delete(`/user/${user.Id}`)
      .set('Accept', 'application/json')
      .set('Authorization', 'Bearer ' + accessToken)
      .expect(200);

    return response;
  });
});
