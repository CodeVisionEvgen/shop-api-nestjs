import { Injectable } from '@nestjs/common';
import { SignUpAuthDto } from './dto/signup-auth.dto';
import { User } from 'src/user/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@Injectable()
export class AuthService {
  constructor(@InjectRepository(User) private userRepo: Repository<User>) {}
  async createUserJWT(signUpAuthDto: SignUpAuthDto) {
    return this.userRepo.save({ ...signUpAuthDto, Provider: 'JWT' });
  }
}
