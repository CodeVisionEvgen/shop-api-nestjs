import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';

@Injectable()
export class UserService {
  constructor(@InjectRepository(User) private userRepo: Repository<User>) {}
  create(createUserDto: CreateUserDto) {
    return this.userRepo.save(createUserDto);
  }

  findAll() {
    return this.userRepo.find();
  }

  findOne(Id: number) {
    return this.userRepo.findOneBy({ Id });
  }

  async update(Id: number, updateUserDto: UpdateUserDto) {
    await this.userRepo.update({ Id }, updateUserDto);
    return this.userRepo.findOneBy({ Id });
  }

  remove(Id: number) {
    return this.userRepo.delete({ Id });
  }
}
